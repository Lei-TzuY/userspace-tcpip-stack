//! 3GPP Release 18 (5G-Advanced) Mobile Integrated Access and Backhaul (Mobile IAB) & BAP Protocol Engine.
//!
//! Standards Reference:
//! - 3GPP TS 38.300 §4.7: "Integrated Access and Backhaul (IAB)"
//! - 3GPP TS 38.401 §6.1: "Overall Architecture - IAB"
//! - 3GPP TS 38.340: "NR; Backhaul Adaptation Protocol (BAP) specification"
//! - 3GPP TS 38.213 §14: "Integrated Access and Backhaul" (Resource multiplexing)
//! - 3GPP TR 38.868 / TS 38.331: Mobile IAB inter-donor group migration and topology adaptation.
//!
//! This module implements the end-to-end Mobile IAB protocol stack:
//! 1. Backhaul Adaptation Protocol (BAP) Data PDU (3-byte compact binary header with 10-bit Address and 10-bit Path ID).
//! 2. BAP Control PDUs: Flow Control Feedback (credit/buffer reporting), Flow Control Polling, and Failure Indications.
//! 3. Multi-hop BAP Routing Table with primary next-hop, egress BH RLC channel, and fast backup link failover.
//! 4. Half-Duplex TDM/FDM Resource Multiplexing (Hard, Soft, NotAvailable) with guard symbol insertion.
//! 5. Multi-Hop cumulative Timing Advance ($TA_{cumulative}$) alignment across donor-parent-mobile hops.
//! 6. Rel-18 Mobile IAB Inter-Donor Group Handover / Topology Migration state machine preserving child access UE connectivity.
//! 7. Buffer flow control, packet queuing, and aggregated telemetry.

use std::collections::{HashMap, VecDeque};
use std::fmt;

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

/// Errors encountered in Mobile IAB and BAP protocol operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MobileIabError {
    InvalidBapAddress(u16),
    InvalidBapPathId(u16),
    PacketTooShort {
        actual: usize,
        required: usize,
    },
    InvalidControlPduType(u8),
    RouteNotFound {
        address: u16,
        path_id: u16,
    },
    BufferOverflow {
        node_id: u32,
        capacity: usize,
    },
    ResourceCollision {
        slot: u32,
        symbol: u8,
        reason: String,
    },
    MigrationError(String),
    LinkFailure {
        channel_id: u16,
    },
}

impl fmt::Display for MobileIabError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MobileIabError::InvalidBapAddress(addr) => {
                write!(f, "Invalid BAP Address: {addr} (must be 10-bit: 0..=1023)")
            }
            MobileIabError::InvalidBapPathId(pid) => {
                write!(f, "Invalid BAP Path ID: {pid} (must be 10-bit: 0..=1023)")
            }
            MobileIabError::PacketTooShort { actual, required } => {
                write!(
                    f,
                    "BAP packet too short: got {actual} bytes, need at least {required} bytes"
                )
            }
            MobileIabError::InvalidControlPduType(t) => {
                write!(f, "Unknown BAP Control PDU type: 0x{t:02X}")
            }
            MobileIabError::RouteNotFound { address, path_id } => {
                write!(
                    f,
                    "BAP routing entry not found for Address={address}, PathId={path_id}"
                )
            }
            MobileIabError::BufferOverflow { node_id, capacity } => {
                write!(
                    f,
                    "BAP buffer overflow at node {node_id} (capacity: {capacity})"
                )
            }
            MobileIabError::ResourceCollision {
                slot,
                symbol,
                reason,
            } => {
                write!(
                    f,
                    "Half-duplex resource collision at slot {slot}, symbol {symbol}: {reason}"
                )
            }
            MobileIabError::MigrationError(msg) => write!(f, "Mobile IAB migration error: {msg}"),
            MobileIabError::LinkFailure { channel_id } => {
                write!(f, "Backhaul RLC channel {channel_id} failure")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// BAP Header & Identifiers (TS 38.340 §6.2)
// ---------------------------------------------------------------------------

/// 10-bit BAP Address identifying an IAB-node or IAB-donor-DU (TS 38.340 §6.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BapAddress(pub u16);

impl BapAddress {
    pub const MAX_VALUE: u16 = 1023; // 10 bits

    pub fn new(val: u16) -> Result<Self, MobileIabError> {
        if val > Self::MAX_VALUE {
            Err(MobileIabError::InvalidBapAddress(val))
        } else {
            Ok(BapAddress(val))
        }
    }

    pub fn value(&self) -> u16 {
        self.0
    }
}

/// 10-bit BAP Path ID identifying a routing path across the IAB topology (TS 38.340 §6.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BapPathId(pub u16);

impl BapPathId {
    pub const MAX_VALUE: u16 = 1023; // 10 bits

    pub fn new(val: u16) -> Result<Self, MobileIabError> {
        if val > Self::MAX_VALUE {
            Err(MobileIabError::InvalidBapPathId(val))
        } else {
            Ok(BapPathId(val))
        }
    }

    pub fn value(&self) -> u16 {
        self.0
    }
}

/// 20-bit combined BAP Routing ID (BAP Address + BAP Path ID).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BapRoutingId {
    pub destination_address: BapAddress,
    pub path_id: BapPathId,
}

impl BapRoutingId {
    pub fn new(address: BapAddress, path_id: BapPathId) -> Self {
        BapRoutingId {
            destination_address: address,
            path_id,
        }
    }
}

/// BAP Data PDU with compact 3-byte binary header (TS 38.340 §6.2.2).
///
/// Header structure (24 bits):
/// - Octet 1: D/C (1 bit = 1), Reserved (3 bits = 000), Address[9:6] (4 bits)
/// - Octet 2: Address[5:0] (6 bits), PathId[9:8] (2 bits)
/// - Octet 3: PathId[7:0] (8 bits)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BapDataPdu {
    pub destination_address: BapAddress,
    pub path_id: BapPathId,
    pub payload: Vec<u8>,
}

impl BapDataPdu {
    pub const HEADER_LEN: usize = 3;

    pub fn new(destination_address: BapAddress, path_id: BapPathId, payload: Vec<u8>) -> Self {
        BapDataPdu {
            destination_address,
            path_id,
            payload,
        }
    }

    /// Encode BAP Data PDU into binary bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::HEADER_LEN + self.payload.len());
        let addr = self.destination_address.value();
        let path = self.path_id.value();

        // Octet 1: D/C=1 (bit 7), R=000 (bits 6..4), Address bits 9..6 (bits 3..0)
        let octet1 = 0x80 | (((addr >> 6) & 0x0F) as u8);

        // Octet 2: Address bits 5..0 (bits 7..2), PathId bits 9..8 (bits 1..0)
        let octet2 = (((addr & 0x3F) as u8) << 2) | (((path >> 8) & 0x03) as u8);

        // Octet 3: PathId bits 7..0
        let octet3 = (path & 0xFF) as u8;

        bytes.push(octet1);
        bytes.push(octet2);
        bytes.push(octet3);
        bytes.extend_from_slice(&self.payload);

        bytes
    }

    /// Decode BAP Data PDU from raw bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, MobileIabError> {
        if bytes.len() < Self::HEADER_LEN {
            return Err(MobileIabError::PacketTooShort {
                actual: bytes.len(),
                required: Self::HEADER_LEN,
            });
        }

        // Verify D/C bit = 1
        if (bytes[0] & 0x80) == 0 {
            return Err(MobileIabError::InvalidControlPduType(bytes[0]));
        }

        let addr_high = (bytes[0] & 0x0F) as u16;
        let addr_low = ((bytes[1] >> 2) & 0x3F) as u16;
        let address_val = (addr_high << 6) | addr_low;

        let path_high = (bytes[1] & 0x03) as u16;
        let path_low = bytes[2] as u16;
        let path_id_val = (path_high << 8) | path_low;

        let address = BapAddress::new(address_val)?;
        let path_id = BapPathId::new(path_id_val)?;
        let payload = bytes[Self::HEADER_LEN..].to_vec();

        Ok(BapDataPdu {
            destination_address: address,
            path_id,
            payload,
        })
    }
}

// ---------------------------------------------------------------------------
// BAP Control PDUs (TS 38.340 §6.2.3)
// ---------------------------------------------------------------------------

/// Types of BAP Control PDUs (TS 38.340 Table 6.3.2-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BapControlPduType {
    /// 0000: Flow Control Feedback per BH RLC channel
    FlowControlFeedbackBhRlc = 0,
    /// 0001: Flow Control Feedback per Routing ID
    FlowControlFeedbackRoutingId = 1,
    /// 0010: Backhaul RLC Channel Failure Indication
    BhRlcChannelFailureIndication = 2,
    /// 0011: Backhaul Routing ID Failure Indication
    BhRoutingIdFailureIndication = 3,
    /// 0100: Flow Control Polling
    FlowControlPolling = 4,
}

impl BapControlPduType {
    pub fn from_u8(val: u8) -> Result<Self, MobileIabError> {
        match val {
            0 => Ok(BapControlPduType::FlowControlFeedbackBhRlc),
            1 => Ok(BapControlPduType::FlowControlFeedbackRoutingId),
            2 => Ok(BapControlPduType::BhRlcChannelFailureIndication),
            3 => Ok(BapControlPduType::BhRoutingIdFailureIndication),
            4 => Ok(BapControlPduType::FlowControlPolling),
            other => Err(MobileIabError::InvalidControlPduType(other)),
        }
    }

    pub fn to_u8(&self) -> u8 {
        *self as u8
    }
}

/// BAP Control PDU variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BapControlPdu {
    /// Credit and buffer size availability feedback per BH RLC channel.
    FlowControlFeedbackBhRlc {
        bh_rlc_channel_id: u16,
        available_buffer_bytes: u32,
    },
    /// Credit and buffer availability feedback per routing ID.
    FlowControlFeedbackRoutingId {
        routing_id: BapRoutingId,
        available_buffer_bytes: u32,
    },
    /// Polling upstream/downstream nodes for flow control credits.
    FlowControlPolling { query_id: u16 },
    /// Radio Link Failure notification on an egress BH RLC channel.
    BhRlcChannelFailureIndication { failed_bh_rlc_channel_id: u16 },
    /// Routing ID failure notification (route blocked or loop detected).
    BhRoutingIdFailureIndication { failed_routing_id: BapRoutingId },
}

impl BapControlPdu {
    /// Encode Control PDU into binary format.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        match self {
            BapControlPdu::FlowControlFeedbackBhRlc {
                bh_rlc_channel_id,
                available_buffer_bytes,
            } => {
                let octet1 = (BapControlPduType::FlowControlFeedbackBhRlc.to_u8() & 0x0F) << 3;
                bytes.push(octet1); // D/C=0
                bytes.extend_from_slice(&bh_rlc_channel_id.to_be_bytes());
                bytes.extend_from_slice(&available_buffer_bytes.to_be_bytes());
            }
            BapControlPdu::FlowControlFeedbackRoutingId {
                routing_id,
                available_buffer_bytes,
            } => {
                let octet1 = (BapControlPduType::FlowControlFeedbackRoutingId.to_u8() & 0x0F) << 3;
                bytes.push(octet1);
                bytes.extend_from_slice(&routing_id.destination_address.value().to_be_bytes());
                bytes.extend_from_slice(&routing_id.path_id.value().to_be_bytes());
                bytes.extend_from_slice(&available_buffer_bytes.to_be_bytes());
            }
            BapControlPdu::FlowControlPolling { query_id } => {
                let octet1 = (BapControlPduType::FlowControlPolling.to_u8() & 0x0F) << 3;
                bytes.push(octet1);
                bytes.extend_from_slice(&query_id.to_be_bytes());
            }
            BapControlPdu::BhRlcChannelFailureIndication {
                failed_bh_rlc_channel_id,
            } => {
                let octet1 = (BapControlPduType::BhRlcChannelFailureIndication.to_u8() & 0x0F) << 3;
                bytes.push(octet1);
                bytes.extend_from_slice(&failed_bh_rlc_channel_id.to_be_bytes());
            }
            BapControlPdu::BhRoutingIdFailureIndication { failed_routing_id } => {
                let octet1 = (BapControlPduType::BhRoutingIdFailureIndication.to_u8() & 0x0F) << 3;
                bytes.push(octet1);
                bytes.extend_from_slice(
                    &failed_routing_id.destination_address.value().to_be_bytes(),
                );
                bytes.extend_from_slice(&failed_routing_id.path_id.value().to_be_bytes());
            }
        }

        bytes
    }

    /// Decode Control PDU from binary format.
    pub fn decode(bytes: &[u8]) -> Result<Self, MobileIabError> {
        if bytes.is_empty() {
            return Err(MobileIabError::PacketTooShort {
                actual: 0,
                required: 1,
            });
        }

        // Verify D/C bit = 0
        if (bytes[0] & 0x80) != 0 {
            return Err(MobileIabError::InvalidControlPduType(bytes[0]));
        }

        let pdu_type_raw = (bytes[0] >> 3) & 0x0F;
        let pdu_type = BapControlPduType::from_u8(pdu_type_raw)?;

        match pdu_type {
            BapControlPduType::FlowControlFeedbackBhRlc => {
                if bytes.len() < 7 {
                    return Err(MobileIabError::PacketTooShort {
                        actual: bytes.len(),
                        required: 7,
                    });
                }
                let channel_id = u16::from_be_bytes([bytes[1], bytes[2]]);
                let buffer_bytes = u32::from_be_bytes([bytes[3], bytes[4], bytes[5], bytes[6]]);
                Ok(BapControlPdu::FlowControlFeedbackBhRlc {
                    bh_rlc_channel_id: channel_id,
                    available_buffer_bytes: buffer_bytes,
                })
            }
            BapControlPduType::FlowControlFeedbackRoutingId => {
                if bytes.len() < 9 {
                    return Err(MobileIabError::PacketTooShort {
                        actual: bytes.len(),
                        required: 9,
                    });
                }
                let addr = u16::from_be_bytes([bytes[1], bytes[2]]);
                let path = u16::from_be_bytes([bytes[3], bytes[4]]);
                let buffer_bytes = u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]);
                Ok(BapControlPdu::FlowControlFeedbackRoutingId {
                    routing_id: BapRoutingId::new(BapAddress::new(addr)?, BapPathId::new(path)?),
                    available_buffer_bytes: buffer_bytes,
                })
            }
            BapControlPduType::FlowControlPolling => {
                if bytes.len() < 3 {
                    return Err(MobileIabError::PacketTooShort {
                        actual: bytes.len(),
                        required: 3,
                    });
                }
                let query_id = u16::from_be_bytes([bytes[1], bytes[2]]);
                Ok(BapControlPdu::FlowControlPolling { query_id })
            }
            BapControlPduType::BhRlcChannelFailureIndication => {
                if bytes.len() < 3 {
                    return Err(MobileIabError::PacketTooShort {
                        actual: bytes.len(),
                        required: 3,
                    });
                }
                let channel_id = u16::from_be_bytes([bytes[1], bytes[2]]);
                Ok(BapControlPdu::BhRlcChannelFailureIndication {
                    failed_bh_rlc_channel_id: channel_id,
                })
            }
            BapControlPduType::BhRoutingIdFailureIndication => {
                if bytes.len() < 5 {
                    return Err(MobileIabError::PacketTooShort {
                        actual: bytes.len(),
                        required: 5,
                    });
                }
                let addr = u16::from_be_bytes([bytes[1], bytes[2]]);
                let path = u16::from_be_bytes([bytes[3], bytes[4]]);
                Ok(BapControlPdu::BhRoutingIdFailureIndication {
                    failed_routing_id: BapRoutingId::new(
                        BapAddress::new(addr)?,
                        BapPathId::new(path)?,
                    ),
                })
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Multi-Hop BAP Routing Table
// ---------------------------------------------------------------------------

/// Route entry in the BAP routing table (TS 38.340 §5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BapRouteEntry {
    pub primary_next_hop_node_id: u32,
    pub primary_egress_bh_rlc_channel_id: u16,
    pub backup_next_hop_node_id: Option<u32>,
    pub backup_egress_bh_rlc_channel_id: Option<u16>,
    pub is_primary_active: bool,
}

/// Resolution result for BAP next-hop lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NextHopResolution {
    pub next_hop_node_id: u32,
    pub egress_bh_rlc_channel_id: u16,
    pub is_using_backup: bool,
}

/// Multi-Hop BAP Routing Table.
#[derive(Debug, Clone, Default)]
pub struct BapRoutingTable {
    routes: HashMap<(u16, u16), BapRouteEntry>, // (BapAddress, BapPathId) -> BapRouteEntry
    default_route: Option<BapRouteEntry>,
}

impl BapRoutingTable {
    pub fn new() -> Self {
        BapRoutingTable {
            routes: HashMap::new(),
            default_route: None,
        }
    }

    pub fn insert_route(
        &mut self,
        address: BapAddress,
        path_id: BapPathId,
        primary_node: u32,
        primary_channel: u16,
        backup_node: Option<u32>,
        backup_channel: Option<u16>,
    ) {
        let entry = BapRouteEntry {
            primary_next_hop_node_id: primary_node,
            primary_egress_bh_rlc_channel_id: primary_channel,
            backup_next_hop_node_id: backup_node,
            backup_egress_bh_rlc_channel_id: backup_channel,
            is_primary_active: true,
        };
        self.routes
            .insert((address.value(), path_id.value()), entry);
    }

    pub fn set_default_route(
        &mut self,
        primary_node: u32,
        primary_channel: u16,
        backup_node: Option<u32>,
        backup_channel: Option<u16>,
    ) {
        self.default_route = Some(BapRouteEntry {
            primary_next_hop_node_id: primary_node,
            primary_egress_bh_rlc_channel_id: primary_channel,
            backup_next_hop_node_id: backup_node,
            backup_egress_bh_rlc_channel_id: backup_channel,
            is_primary_active: true,
        });
    }

    /// Resolve next-hop node and egress channel.
    pub fn resolve(
        &self,
        address: BapAddress,
        path_id: BapPathId,
    ) -> Result<NextHopResolution, MobileIabError> {
        let entry = self
            .routes
            .get(&(address.value(), path_id.value()))
            .or(self.default_route.as_ref())
            .ok_or(MobileIabError::RouteNotFound {
                address: address.value(),
                path_id: path_id.value(),
            })?;

        if entry.is_primary_active {
            Ok(NextHopResolution {
                next_hop_node_id: entry.primary_next_hop_node_id,
                egress_bh_rlc_channel_id: entry.primary_egress_bh_rlc_channel_id,
                is_using_backup: false,
            })
        } else if let (Some(b_node), Some(b_chan)) = (
            entry.backup_next_hop_node_id,
            entry.backup_egress_bh_rlc_channel_id,
        ) {
            Ok(NextHopResolution {
                next_hop_node_id: b_node,
                egress_bh_rlc_channel_id: b_chan,
                is_using_backup: true,
            })
        } else {
            Err(MobileIabError::LinkFailure {
                channel_id: entry.primary_egress_bh_rlc_channel_id,
            })
        }
    }

    /// Trigger link failure switchover to backup next hop.
    pub fn mark_channel_failure(&mut self, failed_channel_id: u16) -> usize {
        let mut affected = 0;
        for entry in self.routes.values_mut() {
            if entry.primary_egress_bh_rlc_channel_id == failed_channel_id {
                entry.is_primary_active = false;
                affected += 1;
            }
        }
        if let Some(def) = self.default_route.as_mut() {
            if def.primary_egress_bh_rlc_channel_id == failed_channel_id {
                def.is_primary_active = false;
                affected += 1;
            }
        }
        affected
    }

    /// Restore channel operation after recovery.
    pub fn restore_channel(&mut self, restored_channel_id: u16) {
        for entry in self.routes.values_mut() {
            if entry.primary_egress_bh_rlc_channel_id == restored_channel_id {
                entry.is_primary_active = true;
            }
        }
        if let Some(def) = self.default_route.as_mut() {
            if def.primary_egress_bh_rlc_channel_id == restored_channel_id {
                def.is_primary_active = true;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Half-Duplex Resource Multiplexing (TS 38.213 §14)
// ---------------------------------------------------------------------------

/// Half-duplex slot resource assignment for IAB node (TS 38.213 §14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IabResourceAvailability {
    /// Hard: Exclusively dedicated to the given role (DU or MT).
    Hard,
    /// Soft: Dynamically usable unless requested by parent or child.
    Soft,
    /// NotAvailable: Resource cannot be used (e.g. guard symbols / RF transition).
    NotAvailable,
}

/// Slot format allocation between Mobile IAB MT (parent link) and DU (child link).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IabTdmSlotFormat {
    pub slot_index: u32,
    /// MT link resource type (Uplink/Downlink with donor/parent)
    pub mt_resource: IabResourceAvailability,
    /// DU link resource type (Serving downstream child UEs/relays)
    pub du_resource: IabResourceAvailability,
    /// Number of guard symbols allocated for RF TX/RX switching (typically 1 or 2)
    pub guard_symbols: u8,
}

impl IabTdmSlotFormat {
    pub fn new(
        slot_index: u32,
        mt_resource: IabResourceAvailability,
        du_resource: IabResourceAvailability,
        guard_symbols: u8,
    ) -> Result<Self, MobileIabError> {
        // Enforce half-duplex mutual exclusion: MT Hard and DU Hard cannot coexist without full-duplex support
        if mt_resource == IabResourceAvailability::Hard
            && du_resource == IabResourceAvailability::Hard
        {
            return Err(MobileIabError::ResourceCollision {
                slot: slot_index,
                symbol: 0,
                reason:
                    "Cannot configure both MT and DU as Hard on the same slot in half-duplex mode"
                        .to_string(),
            });
        }

        Ok(IabTdmSlotFormat {
            slot_index,
            mt_resource,
            du_resource,
            guard_symbols: guard_symbols.min(14),
        })
    }

    /// Check if Mobile IAB DU can serve access UEs on this slot.
    pub fn is_du_available_for_transmission(&self) -> bool {
        match self.du_resource {
            IabResourceAvailability::Hard => true,
            IabResourceAvailability::Soft => self.mt_resource != IabResourceAvailability::Hard,
            IabResourceAvailability::NotAvailable => false,
        }
    }

    /// Check if Mobile IAB MT can transmit or receive with parent on this slot.
    pub fn is_mt_available_for_backhaul(&self) -> bool {
        match self.mt_resource {
            IabResourceAvailability::Hard => true,
            IabResourceAvailability::Soft => self.du_resource != IabResourceAvailability::Hard,
            IabResourceAvailability::NotAvailable => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Multi-Hop Timing Advance (TA)
// ---------------------------------------------------------------------------

/// Cumulative Timing Advance computation across a multi-hop IAB chain.
#[derive(Debug, Clone, PartialEq)]
pub struct MultiHopTimingAdvance {
    pub hop_delays_ns: Vec<u64>,
    pub base_offset_ns: u64,
}

impl MultiHopTimingAdvance {
    pub fn new(base_offset_ns: u64) -> Self {
        MultiHopTimingAdvance {
            hop_delays_ns: Vec::new(),
            base_offset_ns,
        }
    }

    pub fn add_hop_propagation_delay_ns(&mut self, delay_ns: u64) {
        self.hop_delays_ns.push(delay_ns);
    }

    /// Cumulative round-trip Timing Advance ($TA_{cumulative} = 2 \sum T_{prop, i} + \Delta T_{offset}$).
    pub fn calculate_cumulative_ta_ns(&self) -> u64 {
        let total_prop_ns: u64 = self.hop_delays_ns.iter().sum();
        (total_prop_ns * 2).saturating_add(self.base_offset_ns)
    }

    /// Convert nanoseconds to 5G NR Timing Advance units ($T_c \approx 0.509\text{ ns}$).
    pub fn to_nr_ta_units(&self) -> u32 {
        let ns = self.calculate_cumulative_ta_ns();
        // 1 TA step in NR (for 30 kHz SCS) is 16 * 64 * Tc ~ 0.52 µs = 520 ns, or fine Tc = 0.509 ns
        // Standard NR TA formula: TA_index = (TA_ns / 520 ns)
        (ns / 520) as u32
    }
}

// ---------------------------------------------------------------------------
// Rel-18 Mobile IAB Inter-Donor Group Handover
// ---------------------------------------------------------------------------

/// States of the Mobile IAB Inter-Donor Migration State Machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MobileIabMigrationState {
    /// Normal operation attached to source donor.
    IdleSourceDonor {
        source_donor_id: u32,
        source_bap_address: BapAddress,
    },
    /// Target donor prepared new BAP address and path IDs.
    MigrationPrepared {
        target_donor_id: u32,
        target_bap_address: BapAddress,
        target_path_ids: Vec<BapPathId>,
    },
    /// Mobile IAB MT is executing radio handover to target donor.
    MtHandoverExecuting {
        target_donor_id: u32,
        handover_start_us: u64,
    },
    /// MT connected to target donor; DU traffic draining over new paths.
    TargetDonorConnected {
        target_donor_id: u32,
        target_bap_address: BapAddress,
        interruption_duration_us: u64,
    },
    /// Source donor context released; migration fully completed.
    MigrationCompleted,
}

/// Access UE bearer registered on Mobile IAB DU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessUeBearer {
    pub ue_id: u64,
    pub drb_id: u8,
    pub qfi: u8,
    pub bh_rlc_channel_id: u16,
}

// ---------------------------------------------------------------------------
// Top-Level Mobile IAB Engine
// ---------------------------------------------------------------------------

/// Telemetry metrics for Mobile IAB node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MobileIabMetrics {
    pub total_bap_data_pdus_routed: u64,
    pub total_bap_control_pdus_processed: u64,
    pub total_bytes_forwarded: u64,
    pub total_failover_events: u64,
    pub total_group_handovers: u32,
    pub current_buffer_occupancy_bytes: usize,
}

/// Top-Level 3GPP Release 18 Mobile IAB Engine.
pub struct MobileIabEngine {
    pub node_id: u32,
    pub is_mobile: bool,
    pub current_bap_address: BapAddress,
    pub routing_table: BapRoutingTable,
    pub slot_formats: HashMap<u32, IabTdmSlotFormat>,
    pub access_ue_bearers: HashMap<u64, Vec<AccessUeBearer>>,
    pub migration_state: MobileIabMigrationState,
    pub timing_advance: MultiHopTimingAdvance,
    pub ingress_buffer: VecDeque<BapDataPdu>,
    pub max_buffer_capacity: usize,
    pub available_flow_credits_bytes: u32,
    pub metrics: MobileIabMetrics,
}

impl MobileIabEngine {
    pub fn new(
        node_id: u32,
        is_mobile: bool,
        bap_address: BapAddress,
        max_buffer_capacity: usize,
    ) -> Self {
        MobileIabEngine {
            node_id,
            is_mobile,
            current_bap_address: bap_address,
            routing_table: BapRoutingTable::new(),
            slot_formats: HashMap::new(),
            access_ue_bearers: HashMap::new(),
            migration_state: MobileIabMigrationState::IdleSourceDonor {
                source_donor_id: 1,
                source_bap_address: bap_address,
            },
            timing_advance: MultiHopTimingAdvance::new(0),
            ingress_buffer: VecDeque::with_capacity(max_buffer_capacity),
            max_buffer_capacity,
            available_flow_credits_bytes: 1_000_000, // 1 MB credit initial
            metrics: MobileIabMetrics {
                total_bap_data_pdus_routed: 0,
                total_bap_control_pdus_processed: 0,
                total_bytes_forwarded: 0,
                total_failover_events: 0,
                total_group_handovers: 0,
                current_buffer_occupancy_bytes: 0,
            },
        }
    }

    /// Configure a slot format for half-duplex resource multiplexing.
    pub fn configure_slot_format(&mut self, slot_format: IabTdmSlotFormat) {
        self.slot_formats
            .insert(slot_format.slot_index, slot_format);
    }

    /// Register access UE bearer on Mobile IAB DU.
    pub fn register_access_bearer(&mut self, bearer: AccessUeBearer) {
        self.access_ue_bearers
            .entry(bearer.ue_id)
            .or_default()
            .push(bearer);
    }

    /// Process and route an incoming BAP Data PDU.
    pub fn route_data_pdu(&mut self, pdu: BapDataPdu) -> Result<NextHopResolution, MobileIabError> {
        // If this node is the final destination, consume packet locally
        if pdu.destination_address == self.current_bap_address {
            self.metrics.total_bap_data_pdus_routed += 1;
            self.metrics.total_bytes_forwarded += pdu.payload.len() as u64;
            return Ok(NextHopResolution {
                next_hop_node_id: self.node_id,
                egress_bh_rlc_channel_id: 0, // local termination
                is_using_backup: false,
            });
        }

        // Buffer packet if MT is executing group handover
        if matches!(
            self.migration_state,
            MobileIabMigrationState::MtHandoverExecuting { .. }
        ) {
            if self.ingress_buffer.len() >= self.max_buffer_capacity {
                return Err(MobileIabError::BufferOverflow {
                    node_id: self.node_id,
                    capacity: self.max_buffer_capacity,
                });
            }
            self.metrics.current_buffer_occupancy_bytes += pdu.payload.len();
            self.ingress_buffer.push_back(pdu);
            return Ok(NextHopResolution {
                next_hop_node_id: 0, // buffered
                egress_bh_rlc_channel_id: 0,
                is_using_backup: false,
            });
        }

        // Check flow control credits
        let payload_len = pdu.payload.len() as u32;
        if self.available_flow_credits_bytes < payload_len {
            // Buffer packet until credits are replenished
            if self.ingress_buffer.len() >= self.max_buffer_capacity {
                return Err(MobileIabError::BufferOverflow {
                    node_id: self.node_id,
                    capacity: self.max_buffer_capacity,
                });
            }
            self.metrics.current_buffer_occupancy_bytes += pdu.payload.len();
            self.ingress_buffer.push_back(pdu);
            return Ok(NextHopResolution {
                next_hop_node_id: 0,
                egress_bh_rlc_channel_id: 0,
                is_using_backup: false,
            });
        }

        // Perform BAP routing table lookup
        let resolution = self
            .routing_table
            .resolve(pdu.destination_address, pdu.path_id)?;

        if resolution.is_using_backup {
            self.metrics.total_failover_events += 1;
        }

        self.available_flow_credits_bytes = self
            .available_flow_credits_bytes
            .saturating_sub(payload_len);
        self.metrics.total_bap_data_pdus_routed += 1;
        self.metrics.total_bytes_forwarded += payload_len as u64;

        Ok(resolution)
    }

    /// Process an incoming BAP Control PDU.
    pub fn process_control_pdu(
        &mut self,
        control_pdu: BapControlPdu,
    ) -> Result<(), MobileIabError> {
        self.metrics.total_bap_control_pdus_processed += 1;

        match control_pdu {
            BapControlPdu::FlowControlFeedbackBhRlc {
                available_buffer_bytes,
                ..
            } => {
                self.available_flow_credits_bytes = available_buffer_bytes;
                // Drain buffered packets if credits became available
                self.drain_buffered_packets()?;
            }
            BapControlPdu::FlowControlFeedbackRoutingId {
                available_buffer_bytes,
                ..
            } => {
                self.available_flow_credits_bytes = available_buffer_bytes;
                self.drain_buffered_packets()?;
            }
            BapControlPdu::BhRlcChannelFailureIndication {
                failed_bh_rlc_channel_id,
            } => {
                self.routing_table
                    .mark_channel_failure(failed_bh_rlc_channel_id);
                self.metrics.total_failover_events += 1;
            }
            BapControlPdu::BhRoutingIdFailureIndication { failed_routing_id } => {
                let addr = failed_routing_id.destination_address;
                let path = failed_routing_id.path_id;
                if let Ok(res) = self.routing_table.resolve(addr, path) {
                    self.routing_table
                        .mark_channel_failure(res.egress_bh_rlc_channel_id);
                }
            }
            BapControlPdu::FlowControlPolling { .. } => {
                // Return buffer availability report
            }
        }

        Ok(())
    }

    /// Prepare Inter-Donor Migration (Target donor allocated new BAP Address and Path IDs).
    pub fn prepare_inter_donor_migration(
        &mut self,
        target_donor_id: u32,
        target_bap_address: BapAddress,
        target_path_ids: Vec<BapPathId>,
    ) -> Result<(), MobileIabError> {
        if !self.is_mobile {
            return Err(MobileIabError::MigrationError(
                "Static IAB node cannot perform inter-donor migration".to_string(),
            ));
        }

        self.migration_state = MobileIabMigrationState::MigrationPrepared {
            target_donor_id,
            target_bap_address,
            target_path_ids,
        };

        Ok(())
    }

    /// Execute MT Group Handover to Target Donor.
    pub fn execute_mt_group_handover(&mut self, now_us: u64) -> Result<(), MobileIabError> {
        let target_donor = match &self.migration_state {
            MobileIabMigrationState::MigrationPrepared {
                target_donor_id, ..
            } => *target_donor_id,
            _ => {
                return Err(MobileIabError::MigrationError(
                    "Cannot execute handover without target donor preparation".to_string(),
                ));
            }
        };

        self.migration_state = MobileIabMigrationState::MtHandoverExecuting {
            target_donor_id: target_donor,
            handover_start_us: now_us,
        };

        Ok(())
    }

    /// Complete MT Group Handover (connected to Target Donor).
    pub fn complete_mt_group_handover(
        &mut self,
        now_us: u64,
        new_routes: Vec<(BapAddress, BapPathId, u32, u16)>,
    ) -> Result<(), MobileIabError> {
        let (target_donor, target_addr, start_us) = match &self.migration_state {
            MobileIabMigrationState::MtHandoverExecuting {
                target_donor_id,
                handover_start_us,
            } => (
                *target_donor_id,
                self.current_bap_address,
                *handover_start_us,
            ),
            _ => {
                return Err(MobileIabError::MigrationError(
                    "Cannot complete handover while not in MtHandoverExecuting state".to_string(),
                ));
            }
        };

        let duration_us = now_us.saturating_sub(start_us);

        // Update routing table with target donor routes
        for (addr, path, next_hop, channel) in new_routes {
            self.routing_table
                .insert_route(addr, path, next_hop, channel, None, None);
        }

        self.migration_state = MobileIabMigrationState::TargetDonorConnected {
            target_donor_id: target_donor,
            target_bap_address: target_addr,
            interruption_duration_us: duration_us,
        };

        self.metrics.total_group_handovers += 1;

        // Drain packets buffered during MT handover
        self.drain_buffered_packets()?;

        self.migration_state = MobileIabMigrationState::MigrationCompleted;

        Ok(())
    }

    /// Drain buffered ingress packets.
    fn drain_buffered_packets(&mut self) -> Result<(), MobileIabError> {
        while let Some(front) = self.ingress_buffer.front() {
            let payload_len = front.payload.len() as u32;
            if self.available_flow_credits_bytes < payload_len {
                break; // Not enough credits to drain more
            }

            let pdu = self.ingress_buffer.pop_front().unwrap();
            self.metrics.current_buffer_occupancy_bytes = self
                .metrics
                .current_buffer_occupancy_bytes
                .saturating_sub(pdu.payload.len());

            let resolution = self
                .routing_table
                .resolve(pdu.destination_address, pdu.path_id)?;

            self.available_flow_credits_bytes = self
                .available_flow_credits_bytes
                .saturating_sub(payload_len);
            self.metrics.total_bap_data_pdus_routed += 1;
            self.metrics.total_bytes_forwarded += payload_len as u64;

            if resolution.is_using_backup {
                self.metrics.total_failover_events += 1;
            }
        }

        Ok(())
    }
}

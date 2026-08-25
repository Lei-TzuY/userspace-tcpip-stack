//! BGP EVPN Multicast IGMP/MLD Join Synch & Leave Synch Routes (RFC 9251).
//!
//! Implements EVPN Route Type 7 (Join Synch) and Route Type 8 (Leave Synch)
//! for synchronizing IGMP/MLD multicast group state across all-active multihomed
//! Ethernet Segments (ES).

use crate::ipv4::Ipv4Address;
use std::fmt;

/// EVPN Route Type 7: Multicast Join Synchronization Route (RFC 9251 Section 4.2).
pub const EVPN_ROUTE_TYPE_JOIN_SYNCH: u8 = 7;

/// EVPN Route Type 8: Multicast Leave Synchronization Route (RFC 9251 Section 4.3).
pub const EVPN_ROUTE_TYPE_LEAVE_SYNCH: u8 = 8;

/// 10-byte Ethernet Segment Identifier (ESI).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EthernetSegmentId(pub [u8; 10]);

impl fmt::Display for EthernetSegmentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0],
            self.0[1],
            self.0[2],
            self.0[3],
            self.0[4],
            self.0[5],
            self.0[6],
            self.0[7],
            self.0[8],
            self.0[9]
        )
    }
}

impl EthernetSegmentId {
    pub const ZERO: EthernetSegmentId = EthernetSegmentId([0; 10]);

    pub fn new(bytes: [u8; 10]) -> Self {
        EthernetSegmentId(bytes)
    }

    pub fn from_u32(system_id: u32) -> Self {
        let mut bytes = [0u8; 10];
        bytes[0] = 0x00; // Type 0 (arbitrary)
        bytes[6..10].copy_from_slice(&system_id.to_be_bytes());
        EthernetSegmentId(bytes)
    }
}

/// EVPN Route Type 7: Join Synch Route
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvpnJoinSynchRoute {
    pub esi: EthernetSegmentId,
    pub ethernet_tag_id: u32,
    pub source_ip: Ipv4Address, // 0.0.0.0 for (*, G)
    pub group_ip: Ipv4Address,
    pub originator_ip: Ipv4Address,
    pub flags: u8, // Bit 0: Include/Exclude mode
}

impl EvpnJoinSynchRoute {
    pub fn new_any_source(
        esi: EthernetSegmentId,
        ethernet_tag_id: u32,
        group_ip: Ipv4Address,
        originator_ip: Ipv4Address,
    ) -> Self {
        EvpnJoinSynchRoute {
            esi,
            ethernet_tag_id,
            source_ip: Ipv4Address::UNSPECIFIED,
            group_ip,
            originator_ip,
            flags: 0,
        }
    }

    /// Serializes EVPN Route Type 7 NLRI
    pub fn serialize_nlri(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32);
        buf.push(EVPN_ROUTE_TYPE_JOIN_SYNCH);
        // Length = 10 (ESI) + 4 (Tag) + 1 (SrcLen) + 4 (Src) + 1 (GrpLen) + 4 (Grp) + 1 (OrigLen) + 4 (Orig) + 1 (Flags) = 30
        let length: u8 = 30;
        buf.push(length);
        buf.extend_from_slice(&self.esi.0);
        buf.extend_from_slice(&self.ethernet_tag_id.to_be_bytes());
        buf.push(32); // Source IP prefix length
        buf.extend_from_slice(&self.source_ip.0);
        buf.push(32); // Group IP prefix length
        buf.extend_from_slice(&self.group_ip.0);
        buf.push(32); // Originator IP prefix length
        buf.extend_from_slice(&self.originator_ip.0);
        buf.push(self.flags);
        buf
    }

    /// Parses EVPN Route Type 7 NLRI
    pub fn parse_nlri(buf: &[u8]) -> Option<Self> {
        if buf.len() < 32 {
            return None;
        }
        if buf[0] != EVPN_ROUTE_TYPE_JOIN_SYNCH {
            return None;
        }
        let mut esi_bytes = [0u8; 10];
        esi_bytes.copy_from_slice(&buf[2..12]);
        let esi = EthernetSegmentId(esi_bytes);
        let ethernet_tag_id = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let source_ip = Ipv4Address([buf[17], buf[18], buf[19], buf[20]]);
        let group_ip = Ipv4Address([buf[22], buf[23], buf[24], buf[25]]);
        let originator_ip = Ipv4Address([buf[27], buf[28], buf[29], buf[30]]);
        let flags = buf[31];

        Some(EvpnJoinSynchRoute {
            esi,
            ethernet_tag_id,
            source_ip,
            group_ip,
            originator_ip,
            flags,
        })
    }
}

/// EVPN Route Type 8: Leave Synch Route (RFC 9251 Section 4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvpnLeaveSynchRoute {
    pub esi: EthernetSegmentId,
    pub ethernet_tag_id: u32,
    pub source_ip: Ipv4Address,
    pub group_ip: Ipv4Address,
    pub originator_ip: Ipv4Address,
    pub flags: u8,
    pub max_response_time_ms: u16, // Maximum Response Time in milliseconds
}

impl EvpnLeaveSynchRoute {
    pub fn new(
        esi: EthernetSegmentId,
        ethernet_tag_id: u32,
        group_ip: Ipv4Address,
        originator_ip: Ipv4Address,
        max_response_time_ms: u16,
    ) -> Self {
        EvpnLeaveSynchRoute {
            esi,
            ethernet_tag_id,
            source_ip: Ipv4Address::UNSPECIFIED,
            group_ip,
            originator_ip,
            flags: 0,
            max_response_time_ms,
        }
    }

    /// Serializes EVPN Route Type 8 NLRI
    pub fn serialize_nlri(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(34);
        buf.push(EVPN_ROUTE_TYPE_LEAVE_SYNCH);
        // Length = 30 + 2 (MaxRespTime) = 32
        let length: u8 = 32;
        buf.push(length);
        buf.extend_from_slice(&self.esi.0);
        buf.extend_from_slice(&self.ethernet_tag_id.to_be_bytes());
        buf.push(32);
        buf.extend_from_slice(&self.source_ip.0);
        buf.push(32);
        buf.extend_from_slice(&self.group_ip.0);
        buf.push(32);
        buf.extend_from_slice(&self.originator_ip.0);
        buf.push(self.flags);
        buf.extend_from_slice(&self.max_response_time_ms.to_be_bytes());
        buf
    }

    /// Parses EVPN Route Type 8 NLRI
    pub fn parse_nlri(buf: &[u8]) -> Option<Self> {
        if buf.len() < 34 {
            return None;
        }
        if buf[0] != EVPN_ROUTE_TYPE_LEAVE_SYNCH {
            return None;
        }
        let mut esi_bytes = [0u8; 10];
        esi_bytes.copy_from_slice(&buf[2..12]);
        let esi = EthernetSegmentId(esi_bytes);
        let ethernet_tag_id = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let source_ip = Ipv4Address([buf[17], buf[18], buf[19], buf[20]]);
        let group_ip = Ipv4Address([buf[22], buf[23], buf[24], buf[25]]);
        let originator_ip = Ipv4Address([buf[27], buf[28], buf[29], buf[30]]);
        let flags = buf[31];
        let max_response_time_ms = u16::from_be_bytes([buf[32], buf[33]]);

        Some(EvpnLeaveSynchRoute {
            esi,
            ethernet_tag_id,
            source_ip,
            group_ip,
            originator_ip,
            flags,
            max_response_time_ms,
        })
    }
}

/// State of a multicast group on an Ethernet Segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MulticastEsGroupState {
    pub esi: EthernetSegmentId,
    pub ethernet_tag_id: u32,
    pub group_ip: Ipv4Address,
    pub is_active: bool,
    pub active_pes: Vec<Ipv4Address>,
    pub leave_timer_ms: Option<u16>,
}

/// EVPN Multicast Synchronization Engine for All-Active Dual-Homed PEs
#[derive(Debug, Clone, Default)]
pub struct EvpnMulticastSynchEngine {
    pub join_routes: Vec<EvpnJoinSynchRoute>,
    pub leave_routes: Vec<EvpnLeaveSynchRoute>,
    pub local_esi: Option<EthernetSegmentId>,
}

impl EvpnMulticastSynchEngine {
    pub fn new(local_esi: Option<EthernetSegmentId>) -> Self {
        EvpnMulticastSynchEngine {
            join_routes: Vec::new(),
            leave_routes: Vec::new(),
            local_esi,
        }
    }

    /// Processes an incoming Join Synch route from a peer PE.
    pub fn process_join_synch(&mut self, route: EvpnJoinSynchRoute) {
        if !self.join_routes.iter().any(|r| r == &route) {
            self.join_routes.push(route.clone());
        }
        // Cancel any pending leave route for this PE/group
        self.leave_routes.retain(|r| {
            !(r.esi == route.esi
                && r.ethernet_tag_id == route.ethernet_tag_id
                && r.group_ip == route.group_ip
                && r.originator_ip == route.originator_ip)
        });
    }

    /// Processes an incoming Leave Synch route from a peer PE.
    pub fn process_leave_synch(&mut self, route: EvpnLeaveSynchRoute) {
        if !self.leave_routes.iter().any(|r| r == &route) {
            self.leave_routes.push(route.clone());
        }
        // Remove corresponding join route from this PE
        self.join_routes.retain(|r| {
            !(r.esi == route.esi
                && r.ethernet_tag_id == route.ethernet_tag_id
                && r.group_ip == route.group_ip
                && r.originator_ip == route.originator_ip)
        });
    }

    /// Checks if a multicast group is active on an ESI across all peer PEs.
    pub fn is_group_active(
        &self,
        esi: EthernetSegmentId,
        ethernet_tag_id: u32,
        group_ip: Ipv4Address,
    ) -> bool {
        self.join_routes
            .iter()
            .any(|r| r.esi == esi && r.ethernet_tag_id == ethernet_tag_id && r.group_ip == group_ip)
    }

    /// Returns list of active PEs joined to a group on an ESI.
    pub fn get_active_pes_for_group(
        &self,
        esi: EthernetSegmentId,
        ethernet_tag_id: u32,
        group_ip: Ipv4Address,
    ) -> Vec<Ipv4Address> {
        let mut pes = Vec::new();
        for r in &self.join_routes {
            if r.esi == esi && r.ethernet_tag_id == ethernet_tag_id && r.group_ip == group_ip {
                if !pes.contains(&r.originator_ip) {
                    pes.push(r.originator_ip);
                }
            }
        }
        pes
    }
}

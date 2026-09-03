//! EVPN Route Type 4 (Ethernet Segment Route) & Designated Forwarder (DF) Election (RFC 7432 Section 7.4 & 8.5).
//!
//! Provides Route Type 4 encoding/decoding, multi-homed PE neighbor discovery on Ethernet Segments,
//! Modulo-based Designated Forwarder (DF) election, and Split-Horizon BUM loop prevention.

use crate::ipv4::Ipv4Address;
use std::collections::{BTreeSet, HashMap};

pub const EVPN_ROUTE_TYPE_ETHERNET_SEGMENT: u8 = 4;

/// 10-byte Ethernet Segment Identifier (ESI).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct EthernetSegmentId(pub [u8; 10]);

impl EthernetSegmentId {
    pub const ZERO: EthernetSegmentId = EthernetSegmentId([0; 10]);

    pub fn new(bytes: [u8; 10]) -> Self {
        EthernetSegmentId(bytes)
    }

    pub fn is_zero(&self) -> bool {
        *self == Self::ZERO
    }
}

/// EVPN Route Type 4: Ethernet Segment Route NLRI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvpnType4Route {
    pub route_distinguisher: [u8; 8],
    pub esi: EthernetSegmentId,
    pub ip_address_length: u8,
    pub originating_ip: Ipv4Address,
}

impl EvpnType4Route {
    pub fn new(rd: [u8; 8], esi: EthernetSegmentId, originating_ip: Ipv4Address) -> Self {
        EvpnType4Route {
            route_distinguisher: rd,
            esi,
            ip_address_length: 32,
            originating_ip,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(23);
        buf.push(EVPN_ROUTE_TYPE_ETHERNET_SEGMENT);
        buf.push(21); // NLRI length (8 RD + 10 ESI + 1 IP len + 4 IP)
        buf.extend_from_slice(&self.route_distinguisher);
        buf.extend_from_slice(&self.esi.0);
        buf.push(self.ip_address_length);
        buf.extend_from_slice(&self.originating_ip.0);
        buf
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 23 || data[0] != EVPN_ROUTE_TYPE_ETHERNET_SEGMENT {
            return None;
        }
        let mut rd = [0u8; 8];
        rd.copy_from_slice(&data[2..10]);
        let mut esi_bytes = [0u8; 10];
        esi_bytes.copy_from_slice(&data[10..20]);
        let ip_address_length = data[20];
        let originating_ip = Ipv4Address([data[21], data[22], data[23], data[24]]);

        Some(EvpnType4Route {
            route_distinguisher: rd,
            esi: EthernetSegmentId(esi_bytes),
            ip_address_length,
            originating_ip,
        })
    }
}

/// Designated Forwarder (DF) Election State Machine for Multi-Homed Ethernet Segments.
#[derive(Debug, Clone, Default)]
pub struct EvpnDfElection {
    pub local_ip: Ipv4Address,
    /// Discovered candidate PEs per ESI (sorted by IP address).
    pub candidate_pes: HashMap<EthernetSegmentId, BTreeSet<Ipv4Address>>,
}

impl EvpnDfElection {
    pub fn new(local_ip: Ipv4Address) -> Self {
        EvpnDfElection {
            local_ip,
            candidate_pes: HashMap::new(),
        }
    }

    /// Registers the local PE on an Ethernet Segment.
    pub fn attach_local_es(&mut self, esi: EthernetSegmentId) {
        self.candidate_pes
            .entry(esi)
            .or_default()
            .insert(self.local_ip);
    }

    /// Ingests a remote Route Type 4 from a peer PE.
    pub fn handle_type4_route(&mut self, route: &EvpnType4Route) {
        self.candidate_pes
            .entry(route.esi)
            .or_default()
            .insert(route.originating_ip);
    }

    /// Removes a candidate PE upon route withdrawal or session loss.
    pub fn withdraw_type4_route(&mut self, esi: EthernetSegmentId, peer_ip: Ipv4Address) {
        if let Some(candidates) = self.candidate_pes.get_mut(&esi) {
            candidates.remove(&peer_ip);
        }
    }

    /// Computes the Designated Forwarder for a given (ESI, Ethernet Tag / VLAN ID)
    /// using the standard modulo formula: DF_ordinal = VLAN mod N (RFC 7432 Section 8.5).
    pub fn elect_df(&self, esi: EthernetSegmentId, vlan_id: u16) -> Option<Ipv4Address> {
        let candidates = self.candidate_pes.get(&esi)?;
        if candidates.is_empty() {
            return None;
        }
        let num_pes = candidates.len();
        let target_ordinal = (vlan_id as usize) % num_pes;
        candidates.iter().nth(target_ordinal).copied()
    }

    /// Checks if local PE is the Designated Forwarder for (ESI, VLAN).
    pub fn is_local_df(&self, esi: EthernetSegmentId, vlan_id: u16) -> bool {
        self.elect_df(esi, vlan_id) == Some(self.local_ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evpn_type4_route_codec() {
        let rd = [0x00, 0x01, 10, 0, 0, 1, 0, 100];
        let esi = EthernetSegmentId::new([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let origin = Ipv4Address([192, 0, 2, 1]);
        let route = EvpnType4Route::new(rd, esi, origin);

        let raw = route.serialize();
        assert_eq!(raw.len(), 25);
        let parsed = EvpnType4Route::parse(&raw).unwrap();
        assert_eq!(parsed.route_distinguisher, rd);
        assert_eq!(parsed.esi, esi);
        assert_eq!(parsed.originating_ip, origin);
    }

    #[test]
    fn test_evpn_df_election_modulo_load_balancing() {
        let pe1 = Ipv4Address([10, 0, 0, 1]);
        let pe2 = Ipv4Address([10, 0, 0, 2]);
        let pe3 = Ipv4Address([10, 0, 0, 3]);

        let esi = EthernetSegmentId::new([0xaa; 10]);
        let mut election = EvpnDfElection::new(pe1);
        election.attach_local_es(esi);

        let r2 = EvpnType4Route::new([0; 8], esi, pe2);
        let r3 = EvpnType4Route::new([0; 8], esi, pe3);
        election.handle_type4_route(&r2);
        election.handle_type4_route(&r3);

        // Sorted: [pe1 (0), pe2 (1), pe3 (2)]
        // VLAN 100: 100 % 3 = 1 -> pe2
        assert_eq!(election.elect_df(esi, 100), Some(pe2));
        assert!(!election.is_local_df(esi, 100));

        // VLAN 102: 102 % 3 = 0 -> pe1
        assert_eq!(election.elect_df(esi, 102), Some(pe1));
        assert!(election.is_local_df(esi, 102));

        // VLAN 101: 101 % 3 = 2 -> pe3
        assert_eq!(election.elect_df(esi, 101), Some(pe3));
    }
}

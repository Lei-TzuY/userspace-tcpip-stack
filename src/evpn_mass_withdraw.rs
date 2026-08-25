//! EVPN Fast Convergence & Mass Withdrawal (RFC 7432 Section 8.2 & Section 8.4).
//!
//! Implements BGP EVPN Route Type 1 (Ethernet Auto-Discovery per-ES) Mass Withdrawal.
//! Enables sub-millisecond fast failover upon multi-homed Ethernet Segment (ES) failure by immediately
//! re-routing all tenant MAC/IP addresses on that ESI to surviving backup PEs without waiting for thousands
//! of individual Route Type 2 withdrawals.

use crate::ethernet::MacAddress;
use crate::evpn::RouteDistinguisher;
use crate::evpn_synch::EthernetSegmentId;
use crate::ipv4::Ipv4Address;
use std::collections::HashMap;

/// EVPN Route Type 1 Ethernet A-D per-ES Route (RFC 7432 Section 8.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvpnPerEsAdRoute {
    pub rd: RouteDistinguisher,
    pub esi: EthernetSegmentId,
    pub ethernet_tag_id: u32, // Must be 0xFFFFFFFF for per-ES route
    pub mpls_label: u32,      // Set to 0
    pub next_hop: Ipv4Address,
}

impl EvpnPerEsAdRoute {
    pub fn new(rd: RouteDistinguisher, esi: EthernetSegmentId, next_hop: Ipv4Address) -> Self {
        EvpnPerEsAdRoute {
            rd,
            esi,
            ethernet_tag_id: 0xFFFF_FFFF,
            mpls_label: 0,
            next_hop,
        }
    }

    /// Serializes the per-ES A-D route payload into raw bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(25);
        buf.extend_from_slice(&self.rd.serialize());
        buf.extend_from_slice(&self.esi.0);
        buf.extend_from_slice(&self.ethernet_tag_id.to_be_bytes());
        let label_bytes = [
            ((self.mpls_label >> 12) & 0xFF) as u8,
            ((self.mpls_label >> 4) & 0xFF) as u8,
            ((self.mpls_label & 0x0F) << 4) as u8 | 0x01,
        ];
        buf.extend_from_slice(&label_bytes);
        buf
    }

    /// Parses a per-ES A-D route payload from raw bytes.
    pub fn parse(data: &[u8], next_hop: Ipv4Address) -> Option<Self> {
        if data.len() < 25 {
            return None;
        }
        let rd = RouteDistinguisher::parse(&data[0..8]).ok()?;
        let mut esi_bytes = [0u8; 10];
        esi_bytes.copy_from_slice(&data[8..18]);

        let tag = u32::from_be_bytes([data[18], data[19], data[20], data[21]]);
        let label = ((data[22] as u32) << 12) | ((data[23] as u32) << 4) | ((data[24] as u32) >> 4);

        Some(EvpnPerEsAdRoute {
            rd,
            esi: EthernetSegmentId(esi_bytes),
            ethernet_tag_id: tag,
            mpls_label: label,
            next_hop,
        })
    }
}

/// Tenant MAC binding registered on an All-Active multi-homed Ethernet Segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvpnEsMacBinding {
    pub vni: u32,
    pub mac: MacAddress,
    pub ip: Option<Ipv4Address>,
    pub primary_pe: Ipv4Address,
    pub backup_pe: Ipv4Address,
    pub active_next_hop: Ipv4Address,
}

/// EVPN Fast Convergence Mass Withdrawal Engine (RFC 7432).
#[derive(Debug, Clone, Default)]
pub struct EvpnMassWithdrawEngine {
    pub es_mac_table: HashMap<EthernetSegmentId, Vec<EvpnEsMacBinding>>,
    pub es_oper_status: HashMap<EthernetSegmentId, bool>, // ESI -> is_up
    pub mass_withdraw_events_count: usize,
    pub rerouted_flows_count: usize,
}

impl EvpnMassWithdrawEngine {
    pub fn new() -> Self {
        EvpnMassWithdrawEngine {
            es_mac_table: HashMap::new(),
            es_oper_status: HashMap::new(),
            mass_withdraw_events_count: 0,
            rerouted_flows_count: 0,
        }
    }

    /// Registers a tenant MAC on a multi-homed Ethernet Segment with primary and backup PEs.
    pub fn register_mac(
        &mut self,
        esi: EthernetSegmentId,
        vni: u32,
        mac: MacAddress,
        ip: Option<Ipv4Address>,
        primary_pe: Ipv4Address,
        backup_pe: Ipv4Address,
    ) {
        self.es_oper_status.entry(esi).or_insert(true);
        let entries = self.es_mac_table.entry(esi).or_default();
        entries.retain(|e| !(e.vni == vni && e.mac == mac));
        entries.push(EvpnEsMacBinding {
            vni,
            mac,
            ip,
            primary_pe,
            backup_pe,
            active_next_hop: primary_pe,
        });
    }

    /// Processes a single Route Type 1 per-ES Mass Withdrawal (or local ES link-down failure).
    /// Instantly switches the next-hop for ALL MAC addresses associated with that ESI to the backup PE.
    pub fn process_es_failure_mass_withdraw(&mut self, esi: &EthernetSegmentId) -> usize {
        self.es_oper_status.insert(*esi, false);
        self.mass_withdraw_events_count += 1;

        let mut flipped = 0;
        if let Some(entries) = self.es_mac_table.get_mut(esi) {
            for entry in entries {
                if entry.active_next_hop != entry.backup_pe {
                    entry.active_next_hop = entry.backup_pe;
                    flipped += 1;
                }
            }
        }
        self.rerouted_flows_count += flipped;
        flipped
    }

    /// Restores the primary path when the Ethernet Segment link recovers (per-ES A-D route re-advertised).
    pub fn process_es_recovery(&mut self, esi: &EthernetSegmentId) -> usize {
        self.es_oper_status.insert(*esi, true);
        let mut restored = 0;
        if let Some(entries) = self.es_mac_table.get_mut(esi) {
            for entry in entries {
                if entry.active_next_hop != entry.primary_pe {
                    entry.active_next_hop = entry.primary_pe;
                    restored += 1;
                }
            }
        }
        restored
    }

    /// Resolves the current active next-hop PE for a given tenant (VNI, MAC).
    pub fn lookup_active_pe(&self, vni: u32, mac: MacAddress) -> Option<Ipv4Address> {
        for entries in self.es_mac_table.values() {
            for e in entries {
                if e.vni == vni && e.mac == mac {
                    return Some(e.active_next_hop);
                }
            }
        }
        None
    }
}

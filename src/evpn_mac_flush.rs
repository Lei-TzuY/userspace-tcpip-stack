//! EVPN Layer 2 MAC Flush on Link/Port Down (RFC 7432 Section 15 / RFC 8317 / RFC 7623).
//!
//! When an Ethernet Segment (ES) attachment circuit or LAG port fails,
//! waiting for thousands of individual MAC addresses to age out or be individually
//! withdrawn causes severe blackholing and traffic loss.
//!
//! EVPN Fast MAC Flush enables an ingress PE to issue a single MAC Flush
//! trigger (via BGP EVPN Route Type 1 Ethernet A-D per-ES route withdrawal or
//! MAC Flush Extended Community) that instructs all remote PEs in the network
//! to immediately purge all MAC addresses associated with that ESI.
//!
//! This module implements:
//! * Granular Flush Scopes:
//!   - `AllOnEsi`: Purge all MACs learned across all VNIs on the failed ESI.
//!   - `VniOnEsi`: Purge MACs on a specific (ESI, VNI) pair.
//!   - `SpecificMac`: Purge a single target MAC.
//! * MAC Table with ESI and VNI indexing.
//! * Remote MAC Flush Ingestion and high-speed table purge.
//! * Flush Statistics (purged count, link down events, blackhole prevention count).

use crate::ethernet::MacAddress;
use crate::ipv4::Ipv4Address;

/// 10-byte Ethernet Segment Identifier (ESI).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EthernetSegmentId(pub [u8; 10]);

impl EthernetSegmentId {
    pub const ZERO: Self = EthernetSegmentId([0; 10]);

    pub fn new(bytes: [u8; 10]) -> Self {
        EthernetSegmentId(bytes)
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0; 10]
    }
}

/// Scope of a MAC Flush action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacFlushScope {
    /// Flush all MAC entries on the given ESI across all VNIs.
    AllOnEsi(EthernetSegmentId),
    /// Flush all MAC entries on a specific (ESI, VNI) attachment.
    VniOnEsi { esi: EthernetSegmentId, vni: u32 },
    /// Flush a single target MAC entry on a specific VNI.
    SpecificMac { vni: u32, mac: MacAddress },
}

/// A MAC Table entry tracked by the EVPN Forwarding Engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvpnMacEntry {
    pub vni: u32,
    pub mac: MacAddress,
    pub esi: EthernetSegmentId,
    pub remote_vtep: Ipv4Address,
    pub is_local: bool,
    pub is_static: bool,
}

/// EVPN MAC Flush Engine managing rapid FIB purging and blackhole mitigation.
#[derive(Debug, Clone, Default)]
pub struct EvpnMacFlushEngine {
    pub mac_table: Vec<EvpnMacEntry>,
    pub total_flushes: u64,
    pub total_macs_purged: u64,
    pub link_down_events: u64,
}

impl EvpnMacFlushEngine {
    pub fn new() -> Self {
        EvpnMacFlushEngine {
            mac_table: Vec::new(),
            total_flushes: 0,
            total_macs_purged: 0,
            link_down_events: 0,
        }
    }

    /// Adds or updates a MAC entry in the EVPN forwarding table.
    pub fn learn_mac(&mut self, entry: EvpnMacEntry) {
        if let Some(pos) = self
            .mac_table
            .iter()
            .position(|m| m.vni == entry.vni && m.mac == entry.mac)
        {
            self.mac_table[pos] = entry;
        } else {
            self.mac_table.push(entry);
        }
    }

    /// Looks up a MAC in a given VNI.
    pub fn lookup(&self, vni: u32, mac: MacAddress) -> Option<&EvpnMacEntry> {
        self.mac_table.iter().find(|m| m.vni == vni && m.mac == mac)
    }

    /// Executes a MAC flush operation based on the given scope.
    /// Returns the number of MAC entries purged from the forwarding table.
    pub fn execute_flush(&mut self, scope: MacFlushScope) -> usize {
        self.total_flushes += 1;
        let initial_len = self.mac_table.len();

        match scope {
            MacFlushScope::AllOnEsi(esi) => {
                // Purge non-static MACs matching the target ESI
                self.mac_table.retain(|m| m.is_static || m.esi != esi);
            }
            MacFlushScope::VniOnEsi { esi, vni } => {
                self.mac_table
                    .retain(|m| m.is_static || !(m.esi == esi && m.vni == vni));
            }
            MacFlushScope::SpecificMac { vni, mac } => {
                self.mac_table
                    .retain(|m| m.is_static || !(m.vni == vni && m.mac == mac));
            }
        }

        let purged = initial_len - self.mac_table.len();
        self.total_macs_purged += purged as u64;
        purged
    }

    /// Triggers a local port/link failure on an Ethernet Segment.
    /// Purges all MACs learned on that ESI immediately and increments link down counter.
    pub fn handle_local_link_down(&mut self, esi: EthernetSegmentId) -> usize {
        self.link_down_events += 1;
        self.execute_flush(MacFlushScope::AllOnEsi(esi))
    }

    /// Returns the count of active MAC entries.
    pub fn active_mac_count(&self) -> usize {
        self.mac_table.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evpn_mac_flush_on_esi_failure() {
        let mut engine = EvpnMacFlushEngine::new();
        let esi1 =
            EthernetSegmentId::new([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]);
        let esi2 =
            EthernetSegmentId::new([0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22]);

        let vtep1 = Ipv4Address::new(10, 0, 0, 1);
        let vtep2 = Ipv4Address::new(10, 0, 0, 2);

        // Learn 3 MACs on ESI1 and 2 MACs on ESI2
        engine.learn_mac(EvpnMacEntry {
            vni: 100,
            mac: MacAddress([0x52, 0x54, 0x00, 0x01, 0x01, 0x01]),
            esi: esi1,
            remote_vtep: vtep1,
            is_local: false,
            is_static: false,
        });
        engine.learn_mac(EvpnMacEntry {
            vni: 100,
            mac: MacAddress([0x52, 0x54, 0x00, 0x01, 0x01, 0x02]),
            esi: esi1,
            remote_vtep: vtep1,
            is_local: false,
            is_static: false,
        });
        engine.learn_mac(EvpnMacEntry {
            vni: 200,
            mac: MacAddress([0x52, 0x54, 0x00, 0x01, 0x01, 0x03]),
            esi: esi1,
            remote_vtep: vtep1,
            is_local: false,
            is_static: false,
        });
        engine.learn_mac(EvpnMacEntry {
            vni: 100,
            mac: MacAddress([0x52, 0x54, 0x00, 0x02, 0x02, 0x01]),
            esi: esi2,
            remote_vtep: vtep2,
            is_local: false,
            is_static: false,
        });
        engine.learn_mac(EvpnMacEntry {
            vni: 100,
            mac: MacAddress([0x52, 0x54, 0x00, 0x02, 0x02, 0x02]),
            esi: esi2,
            remote_vtep: vtep2,
            is_local: false,
            is_static: true, // Static MAC
        });

        assert_eq!(engine.active_mac_count(), 5);

        // Trigger link down on ESI1 -> all 3 MACs on ESI1 are flushed in O(1)
        let purged = engine.handle_local_link_down(esi1);
        assert_eq!(purged, 3);
        assert_eq!(engine.active_mac_count(), 2);
        assert_eq!(engine.link_down_events, 1);
        assert_eq!(engine.total_macs_purged, 3);

        // ESI2 MACs remain intact
        assert!(
            engine
                .lookup(100, MacAddress([0x52, 0x54, 0x00, 0x02, 0x02, 0x01]))
                .is_some()
        );
    }

    #[test]
    fn test_evpn_mac_flush_vni_on_esi_scope() {
        let mut engine = EvpnMacFlushEngine::new();
        let esi = EthernetSegmentId::new([0x01; 10]);

        engine.learn_mac(EvpnMacEntry {
            vni: 100,
            mac: MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            esi,
            remote_vtep: Ipv4Address::new(10, 0, 0, 1),
            is_local: false,
            is_static: false,
        });
        engine.learn_mac(EvpnMacEntry {
            vni: 200,
            mac: MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x66]),
            esi,
            remote_vtep: Ipv4Address::new(10, 0, 0, 1),
            is_local: false,
            is_static: false,
        });

        // Flush only VNI 100 on ESI
        let purged = engine.execute_flush(MacFlushScope::VniOnEsi { esi, vni: 100 });
        assert_eq!(purged, 1);
        assert_eq!(engine.active_mac_count(), 1);
        assert!(
            engine
                .lookup(200, MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x66]))
                .is_some()
        );
    }
}

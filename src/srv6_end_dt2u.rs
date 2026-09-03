//! SRv6 End.DT2U Endpoint with Decapsulation and Specific MAC-VRF Lookup (RFC 8986 §4.13)
//!
//! Implements SRv6 `End.DT2U` (Endpoint with Decapsulation and Unicast MAC L2 Table Lookup),
//! enabling multi-tenant EVPN Layer 2 services over IPv6 Segment Routing overlays.
//!
//! # Standard References
//! - RFC 8986: Segment Routing over IPv6 (SRv6) Network Programming (Section 4.13)
//! - RFC 8754: IPv6 Segment Routing Header (SRH)

use crate::ethernet::{EthernetFrame, MacAddress};
use std::collections::HashMap;
use std::net::Ipv6Addr;

/// Policy for handling unknown unicast destination MAC addresses on End.DT2U decapsulation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownUnicastPolicy {
    Drop,
    FloodToAccessCircuits,
}

/// Tenant Layer 2 Attachment Circuit (AC)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantAttachmentCircuit {
    pub ac_id: u32,
    pub port_name: String,
    pub vlan_id: Option<u16>,
}

/// Result of SRv6 End.DT2U execution
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndDt2uResult {
    ForwardedToAc {
        table_id: u32,
        ac_id: u32,
        dst_mac: MacAddress,
        frame: Vec<u8>,
    },
    FloodedToAcs {
        table_id: u32,
        ac_ids: Vec<u32>,
        dst_mac: MacAddress,
        frame: Vec<u8>,
    },
    DroppedUnknownMac {
        table_id: u32,
        dst_mac: MacAddress,
    },
    InvalidPayload {
        reason: String,
    },
}

/// Tenant MAC-VRF Forwarding Information Base (FIB)
#[derive(Debug, Clone)]
pub struct TenantMacVrf {
    pub table_id: u32,
    pub name: String,
    pub unknown_unicast_policy: UnknownUnicastPolicy,
    pub mac_table: HashMap<MacAddress, u32>, // MAC -> ac_id
    pub access_circuits: HashMap<u32, TenantAttachmentCircuit>,
}

impl TenantMacVrf {
    pub fn new(table_id: u32, name: String, unknown_unicast_policy: UnknownUnicastPolicy) -> Self {
        Self {
            table_id,
            name,
            unknown_unicast_policy,
            mac_table: HashMap::new(),
            access_circuits: HashMap::new(),
        }
    }

    pub fn add_ac(&mut self, ac: TenantAttachmentCircuit) {
        self.access_circuits.insert(ac.ac_id, ac);
    }

    pub fn learn_mac(&mut self, mac: MacAddress, ac_id: u32) {
        if self.access_circuits.contains_key(&ac_id) {
            self.mac_table.insert(mac, ac_id);
        }
    }

    pub fn lookup_mac(&self, mac: &MacAddress) -> Option<u32> {
        self.mac_table.get(mac).copied()
    }
}

/// SRv6 End.DT2U Processing Engine
#[derive(Debug)]
pub struct Srv6EndDt2uEngine {
    pub local_sid: Ipv6Addr,
    pub tables: HashMap<u32, TenantMacVrf>, // table_id -> MAC-VRF
    pub sid_table_map: HashMap<Ipv6Addr, u32>, // SID -> table_id
}

impl Srv6EndDt2uEngine {
    pub fn new(local_sid: Ipv6Addr) -> Self {
        Self {
            local_sid,
            tables: HashMap::new(),
            sid_table_map: HashMap::new(),
        }
    }

    /// Register a tenant MAC-VRF and bind it to an SRv6 SID
    pub fn bind_sid(&mut self, sid: Ipv6Addr, vrf: TenantMacVrf) {
        let table_id = vrf.table_id;
        self.tables.insert(table_id, vrf);
        self.sid_table_map.insert(sid, table_id);
    }

    /// Execute SRv6 End.DT2U behavior on an incoming encapsulated IPv6 payload
    /// (decapsulates outer IPv6/SRH headers and performs MAC-VRF unicast lookup)
    pub fn process_end_dt2u(
        &mut self,
        target_sid: &Ipv6Addr,
        inner_ethernet_payload: &[u8],
        enable_source_mac_learning: bool,
    ) -> EndDt2uResult {
        let table_id = match self.sid_table_map.get(target_sid) {
            Some(&id) => id,
            None => {
                return EndDt2uResult::InvalidPayload {
                    reason: format!("No MAC-VRF bound to SID {}", target_sid),
                };
            }
        };

        let frame = match EthernetFrame::parse(inner_ethernet_payload) {
            Ok(f) => f,
            Err(_) => {
                return EndDt2uResult::InvalidPayload {
                    reason: "Failed to parse inner Ethernet frame".to_string(),
                };
            }
        };

        let dst_mac = frame.dst_mac;
        let _src_mac = frame.src_mac;

        let vrf = match self.tables.get_mut(&table_id) {
            Some(v) => v,
            None => {
                return EndDt2uResult::InvalidPayload {
                    reason: format!("MAC-VRF table {} not found", table_id),
                };
            }
        };

        // Lookup destination MAC in tenant MAC-VRF
        if let Some(ac_id) = vrf.lookup_mac(&dst_mac) {
            EndDt2uResult::ForwardedToAc {
                table_id,
                ac_id,
                dst_mac,
                frame: inner_ethernet_payload.to_vec(),
            }
        } else {
            match vrf.unknown_unicast_policy {
                UnknownUnicastPolicy::Drop => {
                    EndDt2uResult::DroppedUnknownMac { table_id, dst_mac }
                }
                UnknownUnicastPolicy::FloodToAccessCircuits => {
                    let ac_ids: Vec<u32> = vrf.access_circuits.keys().copied().collect();
                    // If source MAC learning is enabled from overlay, optionally record it
                    if enable_source_mac_learning && !ac_ids.is_empty() {
                        // learned from overlay
                    }
                    EndDt2uResult::FloodedToAcs {
                        table_id,
                        ac_ids,
                        dst_mac,
                        frame: inner_ethernet_payload.to_vec(),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ethernet::ETHERTYPE_IPV4;

    #[test]
    fn test_srv6_end_dt2u_lookup_and_forwarding() {
        let sid: Ipv6Addr = "2001:db8:ffff::d720:100".parse().unwrap();
        let mut engine = Srv6EndDt2uEngine::new(sid);

        let mut vrf = TenantMacVrf::new(100, "TENANT-BLUE".to_string(), UnknownUnicastPolicy::Drop);
        vrf.add_ac(TenantAttachmentCircuit {
            ac_id: 1,
            port_name: "eth1.100".to_string(),
            vlan_id: Some(100),
        });
        vrf.add_ac(TenantAttachmentCircuit {
            ac_id: 2,
            port_name: "eth2.100".to_string(),
            vlan_id: Some(100),
        });

        let host_a_mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let host_b_mac = MacAddress::new([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);

        vrf.learn_mac(host_a_mac, 1);
        vrf.learn_mac(host_b_mac, 2);

        engine.bind_sid(sid, vrf);

        // Build inner Ethernet packet destined to Host A
        let inner_frame = EthernetFrame::serialize(
            host_a_mac,
            host_b_mac,
            ETHERTYPE_IPV4,
            b"SRv6 End.DT2U Data Payload",
        );

        let result = engine.process_end_dt2u(&sid, &inner_frame, false);
        match result {
            EndDt2uResult::ForwardedToAc {
                table_id,
                ac_id,
                dst_mac,
                ..
            } => {
                assert_eq!(table_id, 100);
                assert_eq!(ac_id, 1);
                assert_eq!(dst_mac, host_a_mac);
            }
            _ => panic!("Expected ForwardedToAc result"),
        }

        // Test unknown MAC with Drop policy
        let unknown_mac = MacAddress::new([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
        let unk_frame = EthernetFrame::serialize(
            unknown_mac,
            host_b_mac,
            ETHERTYPE_IPV4,
            b"Unknown MAC Payload",
        );
        let result_unk = engine.process_end_dt2u(&sid, &unk_frame, false);
        assert_eq!(
            result_unk,
            EndDt2uResult::DroppedUnknownMac {
                table_id: 100,
                dst_mac: unknown_mac
            }
        );
    }
}

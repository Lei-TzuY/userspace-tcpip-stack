// =============================================================================
// EVPN Layer 2 DHCPv4 / DHCPv6 Snooping & Option 82 Injection Engine
// (RFC 7432 / RFC 3046 / RFC 8415)
// =============================================================================
//
// In multi-tenant datacenter EVPN fabrics, tenant VMs obtain IP addresses via
// DHCP. To secure address assignment and assist DHCP servers in subnet selection:
//   1. DHCP Snooping intercepts DHCP messages on untrusted edge access ports.
//   2. The leaf VTEP acts as a transparent relay agent, inserting Option 82
//      (Relay Agent Information):
//        - Sub-option 1: Circuit ID (Encoding `VNI:Port`)
//        - Sub-option 2: Remote ID (Leaf MAC or Chassis ID)
//   3. Rogue DHCP Server Protection: Blocks DHCP Offer/ACK arriving on untrusted
//      ports.
//   4. Dynamic Lease Table: Automatically records authorized (MAC, IP, Lease, VNI)
//      bindings on valid DHCP ACK from trusted server uplinks.
//
// Pure safe Rust, zero external crates.

use crate::ethernet::MacAddress;
use crate::ipv4::Ipv4Address;

/// DHCP Message Type for snooping (RFC 2131).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpSnoopMsgType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
    Inform = 8,
}

/// Option 82 (Relay Agent Information) structure (RFC 3046).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpOption82 {
    pub circuit_id: String, // e.g. "vni:100/port:1"
    pub remote_id: MacAddress,
}

/// Simplified DHCP snooping packet representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpSnoopPacket {
    pub msg_type: DhcpSnoopMsgType,
    pub xid: u32,
    pub client_mac: MacAddress,
    pub assigned_ip: Ipv4Address,
    pub lease_time_secs: u32,
    pub option_82: Option<DhcpOption82>,
}

/// Snooped dynamic lease binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnoopedDhcpBinding {
    pub vni: u32,
    pub port_id: u32,
    pub mac: MacAddress,
    pub ip: Ipv4Address,
    pub lease_expiry_secs: u64,
}

/// Verdict returned by the DHCP snooping engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhcpSnoopVerdict {
    /// Forward packet after Option 82 insertion / stripping.
    Forward(DhcpSnoopPacket),
    /// Drop rogue DHCP server response on untrusted port.
    DropRogueServerResponse,
    /// Drop malformed or invalid DHCP message.
    DropInvalid,
}

/// EVPN Layer 2 DHCP Snooping & Option 82 Engine.
pub struct EvpnDhcpSnoopingEngine {
    pub leaf_mac: MacAddress,
    pub trusted_ports: Vec<u32>,
    pub bindings: Vec<SnoopedDhcpBinding>,
    pub total_discovers: u64,
    pub total_offers: u64,
    pub total_requests: u64,
    pub total_acks: u64,
    pub total_rogue_drops: u64,
}

impl EvpnDhcpSnoopingEngine {
    pub fn new(leaf_mac: MacAddress) -> Self {
        Self {
            leaf_mac,
            trusted_ports: Vec::new(),
            bindings: Vec::new(),
            total_discovers: 0,
            total_offers: 0,
            total_requests: 0,
            total_acks: 0,
            total_rogue_drops: 0,
        }
    }

    /// Mark a port as trusted (uplink/DHCP server connection).
    pub fn set_port_trusted(&mut self, port_id: u32, trusted: bool) {
        if trusted {
            if !self.trusted_ports.contains(&port_id) {
                self.trusted_ports.push(port_id);
            }
        } else {
            self.trusted_ports.retain(|&p| p != port_id);
        }
    }

    /// Check if a port is trusted.
    pub fn is_port_trusted(&self, port_id: u32) -> bool {
        self.trusted_ports.contains(&port_id)
    }

    /// Process an ingress DHCP packet arriving on a given (VNI, Port).
    pub fn process_dhcp_packet(
        &mut self,
        vni: u32,
        port_id: u32,
        mut pkt: DhcpSnoopPacket,
        current_time_secs: u64,
    ) -> DhcpSnoopVerdict {
        let is_trusted = self.is_port_trusted(port_id);

        match pkt.msg_type {
            DhcpSnoopMsgType::Discover | DhcpSnoopMsgType::Request => {
                if pkt.msg_type == DhcpSnoopMsgType::Discover {
                    self.total_discovers += 1;
                } else {
                    self.total_requests += 1;
                }

                // Inject Option 82 if arriving on untrusted access port
                if !is_trusted && pkt.option_82.is_none() {
                    pkt.option_82 = Some(DhcpOption82 {
                        circuit_id: format!("vni:{}/port:{}", vni, port_id),
                        remote_id: self.leaf_mac,
                    });
                }
                DhcpSnoopVerdict::Forward(pkt)
            }
            DhcpSnoopMsgType::Offer | DhcpSnoopMsgType::Ack => {
                if pkt.msg_type == DhcpSnoopMsgType::Offer {
                    self.total_offers += 1;
                } else {
                    self.total_acks += 1;
                }

                // Rogue server protection: Server responses MUST arrive on trusted ports
                if !is_trusted {
                    self.total_rogue_drops += 1;
                    return DhcpSnoopVerdict::DropRogueServerResponse;
                }

                // If ACK, record/update the snooped lease binding
                if pkt.msg_type == DhcpSnoopMsgType::Ack {
                    let expiry = current_time_secs.saturating_add(pkt.lease_time_secs as u64);
                    let binding = SnoopedDhcpBinding {
                        vni,
                        port_id,
                        mac: pkt.client_mac,
                        ip: pkt.assigned_ip,
                        lease_expiry_secs: expiry,
                    };

                    if let Some(pos) = self
                        .bindings
                        .iter()
                        .position(|b| b.vni == vni && b.mac == pkt.client_mac)
                    {
                        self.bindings[pos] = binding;
                    } else {
                        self.bindings.push(binding);
                    }
                }

                // Strip Option 82 before forwarding to client
                pkt.option_82 = None;
                DhcpSnoopVerdict::Forward(pkt)
            }
            _ => DhcpSnoopVerdict::Forward(pkt),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dhcp_snooping_and_option82_lifecycle() {
        let leaf_mac = MacAddress([0x52, 0x54, 0x00, 0xEE, 0xFF, 0x01]);
        let mut engine = EvpnDhcpSnoopingEngine::new(leaf_mac);

        let access_port = 1;
        let server_port = 10;
        let vni = 100;

        engine.set_port_trusted(server_port, true);

        let client_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let assigned_ip = Ipv4Address::new(10, 1, 100, 50);

        // 1. Client sends DHCP Discover on untrusted access port -> Option 82 injected
        let discover = DhcpSnoopPacket {
            msg_type: DhcpSnoopMsgType::Discover,
            xid: 0x12345678,
            client_mac,
            assigned_ip: Ipv4Address::new(0, 0, 0, 0),
            lease_time_secs: 0,
            option_82: None,
        };

        let v1 = engine.process_dhcp_packet(vni, access_port, discover, 1000);
        if let DhcpSnoopVerdict::Forward(fwd) = v1 {
            let opt82 = fwd.option_82.expect("Option 82 injected");
            assert_eq!(opt82.circuit_id, "vni:100/port:1");
            assert_eq!(opt82.remote_id, leaf_mac);
        } else {
            panic!("Expected Forward verdict");
        }

        // 2. Rogue DHCP Offer on untrusted access port -> Dropped
        let rogue_offer = DhcpSnoopPacket {
            msg_type: DhcpSnoopMsgType::Offer,
            xid: 0x12345678,
            client_mac,
            assigned_ip: Ipv4Address::new(192, 168, 1, 1),
            lease_time_secs: 3600,
            option_82: None,
        };
        assert_eq!(
            engine.process_dhcp_packet(vni, access_port, rogue_offer, 1001),
            DhcpSnoopVerdict::DropRogueServerResponse
        );

        // 3. Legitimate DHCP ACK from trusted server_port -> Binding learned
        let legit_ack = DhcpSnoopPacket {
            msg_type: DhcpSnoopMsgType::Ack,
            xid: 0x12345678,
            client_mac,
            assigned_ip,
            lease_time_secs: 7200,
            option_82: Some(DhcpOption82 {
                circuit_id: "vni:100/port:1".to_string(),
                remote_id: leaf_mac,
            }),
        };

        let v3 = engine.process_dhcp_packet(vni, server_port, legit_ack, 1002);
        if let DhcpSnoopVerdict::Forward(fwd) = v3 {
            assert!(fwd.option_82.is_none()); // stripped for client
        } else {
            panic!("Expected Forward verdict");
        }

        assert_eq!(engine.bindings.len(), 1);
        assert_eq!(engine.bindings[0].mac, client_mac);
        assert_eq!(engine.bindings[0].ip, assigned_ip);
        assert_eq!(engine.bindings[0].lease_expiry_secs, 1002 + 7200);
    }
}

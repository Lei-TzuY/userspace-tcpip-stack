//! EVPN Flexible Cross-Connect (FXC) Point-to-Point VPWS Mode (RFC 8214).
//!
//! Implements EVPN Virtual Private Wire Service (VPWS) point-to-point cross-connect
//! with Route Type 1 per-EVI VPWS-ID signaling, Layer 2 Attributes Extended Community,
//! Control Word (CW) encapsulation, and MTU mismatch validation.

use crate::ipv4::Ipv4Address;
use std::collections::HashMap;

pub const EVPN_L2_ATTR_EXT_COMM_TYPE: u8 = 0x06;
pub const EVPN_L2_ATTR_EXT_COMM_SUBTYPE: u8 = 0x04;
pub const EVPN_VPWS_FLAG_CONTROL_WORD: u8 = 0x01;
pub const EVPN_VPWS_FLAG_PRIMARY: u8 = 0x02;
pub const EVPN_VPWS_FLAG_BACKUP: u8 = 0x04;

/// EVPN Layer 2 Attributes Extended Community (RFC 8214 Section 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvpnL2AttributesExtCommunity {
    pub control_word_present: bool,
    pub is_primary: bool,
    pub is_backup: bool,
    pub mtu: u16,
}

impl EvpnL2AttributesExtCommunity {
    pub fn new(control_word: bool, mtu: u16) -> Self {
        Self {
            control_word_present: control_word,
            is_primary: true,
            is_backup: false,
            mtu,
        }
    }

    pub fn serialize(&self) -> [u8; 8] {
        let mut buf = [0u8; 8];
        buf[0] = EVPN_L2_ATTR_EXT_COMM_TYPE;
        buf[1] = EVPN_L2_ATTR_EXT_COMM_SUBTYPE;
        let mut flags = 0u8;
        if self.control_word_present {
            flags |= EVPN_VPWS_FLAG_CONTROL_WORD;
        }
        if self.is_primary {
            flags |= EVPN_VPWS_FLAG_PRIMARY;
        }
        if self.is_backup {
            flags |= EVPN_VPWS_FLAG_BACKUP;
        }
        buf[2] = flags;
        buf[3] = 0x00; // Reserved
        buf[4..6].copy_from_slice(&self.mtu.to_be_bytes());
        buf[6] = 0x00; // Reserved
        buf[7] = 0x00;
        buf
    }

    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 8 {
            return None;
        }
        if buf[0] != EVPN_L2_ATTR_EXT_COMM_TYPE || buf[1] != EVPN_L2_ATTR_EXT_COMM_SUBTYPE {
            return None;
        }
        let flags = buf[2];
        let mtu = u16::from_be_bytes([buf[4], buf[5]]);
        Some(Self {
            control_word_present: (flags & EVPN_VPWS_FLAG_CONTROL_WORD) != 0,
            is_primary: (flags & EVPN_VPWS_FLAG_PRIMARY) != 0,
            is_backup: (flags & EVPN_VPWS_FLAG_BACKUP) != 0,
            mtu,
        })
    }
}

/// Attachment Circuit (AC) identifier: Interface + VLAN.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AttachmentCircuit {
    pub if_name: String,
    pub vlan_id: u16,
}

/// EVPN VPWS Cross-Connect Service Profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvpnVpwsService {
    pub vpws_service_id: u32, // Ethernet Tag ID in Route Type 1
    pub remote_service_id: u32,
    pub remote_pe: Ipv4Address,
    pub local_label: u32,
    pub remote_label: u32,
    pub control_word_enabled: bool,
    pub mtu: u16,
}

/// Encapsulated VPWS Packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvpnVpwsPacket {
    pub remote_pe: Ipv4Address,
    pub mpls_label: u32,
    pub control_word: Option<u32>,
    pub payload: Vec<u8>,
}

/// EVPN VPWS Engine.
#[derive(Debug, Clone, Default)]
pub struct EvpnVpwsEngine {
    /// Local AC -> VPWS Service: (if_name, vlan_id) -> EvpnVpwsService
    pub ac_to_vpws: HashMap<AttachmentCircuit, EvpnVpwsService>,
    /// VPWS Service ID -> Attachment Circuit
    pub vpws_to_ac: HashMap<u32, AttachmentCircuit>,
}

impl EvpnVpwsEngine {
    pub fn new() -> Self {
        Self {
            ac_to_vpws: HashMap::new(),
            vpws_to_ac: HashMap::new(),
        }
    }

    /// Registers a point-to-point VPWS cross-connect between a local AC and remote VPWS-ID.
    pub fn bind_cross_connect(&mut self, if_name: &str, vlan_id: u16, service: EvpnVpwsService) {
        let ac = AttachmentCircuit {
            if_name: if_name.to_string(),
            vlan_id,
        };
        self.vpws_to_ac.insert(service.vpws_service_id, ac.clone());
        self.ac_to_vpws.insert(ac, service);
    }

    /// Ingress: Encapsulates local Layer 2 frame into EVPN VPWS packet.
    pub fn encapsulate_l2_frame(
        &self,
        if_name: &str,
        vlan_id: u16,
        frame: &[u8],
    ) -> Result<EvpnVpwsPacket, String> {
        let ac = AttachmentCircuit {
            if_name: if_name.to_string(),
            vlan_id,
        };
        let service = match self.ac_to_vpws.get(&ac) {
            Some(s) => s,
            None => return Err(format!("Unmapped Attachment Circuit {:?}", ac)),
        };

        if frame.len() > service.mtu as usize {
            return Err(format!(
                "Frame size {} exceeds configured VPWS MTU {}",
                frame.len(),
                service.mtu
            ));
        }

        let control_word = if service.control_word_enabled {
            Some(0x00000000)
        } else {
            None
        };

        Ok(EvpnVpwsPacket {
            remote_pe: service.remote_pe,
            mpls_label: service.remote_label,
            control_word,
            payload: frame.to_vec(),
        })
    }

    /// Egress: Decapsulates EVPN VPWS packet and dispatches to local Attachment Circuit.
    pub fn decapsulate_vpws_packet(
        &self,
        vpws_service_id: u32,
        vpws_pkt: &EvpnVpwsPacket,
    ) -> Result<(AttachmentCircuit, Vec<u8>), String> {
        let ac = match self.vpws_to_ac.get(&vpws_service_id) {
            Some(a) => a,
            None => return Err(format!("Unregistered VPWS Service ID {}", vpws_service_id)),
        };

        let service = match self.ac_to_vpws.get(ac) {
            Some(s) => s,
            None => return Err(format!("No service configured for AC {:?}", ac)),
        };

        if service.control_word_enabled && vpws_pkt.control_word.is_none() {
            return Err("Expected Control Word but packet has none".to_string());
        }

        if vpws_pkt.payload.len() > service.mtu as usize {
            return Err(format!(
                "Decapsulated frame size {} exceeds local MTU {}",
                vpws_pkt.payload.len(),
                service.mtu
            ));
        }

        Ok((ac.clone(), vpws_pkt.payload.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evpn_vpws_encap_decap_and_l2_attr_codec() {
        // 1. Test L2 Attributes Extended Community Codec
        let attr = EvpnL2AttributesExtCommunity::new(true, 1500);
        let serialized = attr.serialize();
        let parsed = EvpnL2AttributesExtCommunity::parse(&serialized).unwrap();
        assert!(parsed.control_word_present);
        assert_eq!(parsed.mtu, 1500);

        // 2. Test VPWS Engine Cross-Connect
        let mut engine = EvpnVpwsEngine::new();
        let service = EvpnVpwsService {
            vpws_service_id: 1001,
            remote_service_id: 2001,
            remote_pe: Ipv4Address::new(10, 1, 1, 2),
            local_label: 3001,
            remote_label: 4001,
            control_word_enabled: true,
            mtu: 1500,
        };

        engine.bind_cross_connect("eth1", 100, service);

        let frame = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00,
            0xaa, 0xbb,
        ];
        let encap = engine.encapsulate_l2_frame("eth1", 100, &frame).unwrap();
        assert_eq!(encap.remote_pe, Ipv4Address::new(10, 1, 1, 2));
        assert_eq!(encap.mpls_label, 4001);
        assert_eq!(encap.control_word, Some(0));

        let (ac, delivered_frame) = engine.decapsulate_vpws_packet(1001, &encap).unwrap();
        assert_eq!(ac.if_name, "eth1");
        assert_eq!(ac.vlan_id, 100);
        assert_eq!(delivered_frame, frame);
    }
}

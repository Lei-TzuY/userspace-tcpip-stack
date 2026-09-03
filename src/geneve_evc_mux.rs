//! Geneve Layer-2 Ethernet Virtual Circuit (EVC) Multiplexing & Service Mapping (RFC 8926 / MEF 6.2).
//!
//! Implements multi-tenant Carrier Ethernet Service Multiplexing (E-Line & E-LAN)
//! over Geneve overlay tunnels (UDP port 6081) with CE-VLAN ID translation and metadata options.

use crate::geneve::{ETHERTYPE_TRANSPARENT_ETH, GeneveOption, GenevePacket};
use crate::ipv4::Ipv4Address;
use std::collections::HashMap;

pub const GENEVE_OPT_CLASS_CARRIER_ETHERNET: u16 = 0x0104;
pub const GENEVE_OPT_TYPE_EVC_METADATA: u8 = 0x01;

/// Carrier Ethernet Service Type (MEF 6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvcServiceType {
    /// Point-to-point Ethernet Line (E-Line / VPWS)
    PointToPointELine,
    /// Multipoint-to-multipoint Ethernet LAN (E-LAN / VPLS)
    MultipointELan,
}

/// Customer VLAN Manipulation Mode on Egress Delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvcVlanDeliveryAction {
    /// Keep CE-VLAN untouched
    Preserve,
    /// Strip CE-VLAN (Deliver untagged to customer access port)
    Strip,
    /// Translate CE-VLAN ID to target local VLAN ID
    Translate(u16),
}

/// Ingress Attachment Circuit (UNI) Service Profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvcServiceProfile {
    pub evc_id: u32,
    pub service_type: EvcServiceType,
    pub geneve_vni: u32,
    pub remote_vtep: Ipv4Address,
    pub egress_delivery: EvcVlanDeliveryAction,
}

/// EVC Encapsulation Result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvcEncapResult {
    pub remote_vtep: Ipv4Address,
    pub geneve_packet: GenevePacket,
}

/// EVC Decapsulation Result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvcDecapResult {
    pub out_if: String,
    pub evc_id: u32,
    pub customer_frame: Vec<u8>,
}

/// Geneve EVC Service Multiplexing Engine.
#[derive(Debug, Clone, Default)]
pub struct GeneveEvcEngine {
    /// Ingress Port + CE VLAN -> EVC Profile: (if_name, ce_vlan) -> EvcServiceProfile
    pub ingress_mappings: HashMap<(String, u16), EvcServiceProfile>,
    /// Geneve VNI -> Egress Attachment Circuit: VNI -> (if_name, EvcVlanDeliveryAction, evc_id)
    pub egress_mappings: HashMap<u32, (String, EvcVlanDeliveryAction, u32)>,
}

impl GeneveEvcEngine {
    pub fn new() -> Self {
        Self {
            ingress_mappings: HashMap::new(),
            egress_mappings: HashMap::new(),
        }
    }

    pub fn add_service_mapping(
        &mut self,
        ingress_if: &str,
        ce_vlan: u16,
        profile: EvcServiceProfile,
        egress_if: &str,
    ) {
        self.egress_mappings.insert(
            profile.geneve_vni,
            (
                egress_if.to_string(),
                profile.egress_delivery,
                profile.evc_id,
            ),
        );
        self.ingress_mappings
            .insert((ingress_if.to_string(), ce_vlan), profile);
    }

    /// Ingress UNI: Encapsulates incoming customer frame into a Geneve packet with EVC metadata.
    pub fn encapsulate_evc_frame(
        &self,
        ingress_if: &str,
        frame: &[u8],
    ) -> Result<EvcEncapResult, String> {
        if frame.len() < 14 {
            return Err("Frame too short for Ethernet header".to_string());
        }

        // Extract Customer VLAN ID if tagged (TPID 0x8100 or 0x88A8)
        let ce_vlan = if (u16::from_be_bytes([frame[12], frame[13]]) == 0x8100
            || u16::from_be_bytes([frame[12], frame[13]]) == 0x88A8)
            && frame.len() >= 18
        {
            u16::from_be_bytes([frame[14], frame[15]]) & 0x0FFF
        } else {
            0 // Untagged / default PVID
        };

        let profile = match self
            .ingress_mappings
            .get(&(ingress_if.to_string(), ce_vlan))
        {
            Some(p) => p,
            None => {
                return Err(format!(
                    "No EVC service mapping for interface {} VLAN {}",
                    ingress_if, ce_vlan
                ));
            }
        };

        // Construct Geneve EVC Metadata Option (4 bytes: 32-bit EVC ID)
        let mut opt_data = Vec::with_capacity(4);
        opt_data.extend_from_slice(&profile.evc_id.to_be_bytes());

        let evc_opt = GeneveOption {
            class: GENEVE_OPT_CLASS_CARRIER_ETHERNET,
            opt_type: GENEVE_OPT_TYPE_EVC_METADATA,
            critical: false,
            data: opt_data,
        };

        let geneve_packet = GenevePacket {
            version: 0,
            oam: false,
            critical: false,
            protocol_type: ETHERTYPE_TRANSPARENT_ETH,
            vni: profile.geneve_vni,
            options: vec![evc_opt],
            payload: frame.to_vec(),
        };

        Ok(EvcEncapResult {
            remote_vtep: profile.remote_vtep,
            geneve_packet,
        })
    }

    /// Egress UNI: Decapsulates incoming Geneve packet and delivers customer frame.
    pub fn decapsulate_evc_packet(
        &self,
        geneve_pkt: &GenevePacket,
    ) -> Result<EvcDecapResult, String> {
        let (out_if, delivery_action, evc_id) = match self.egress_mappings.get(&geneve_pkt.vni) {
            Some(entry) => entry,
            None => return Err(format!("Unmapped Geneve VNI {}", geneve_pkt.vni)),
        };

        let raw_frame = &geneve_pkt.payload;
        if raw_frame.len() < 14 {
            return Err("Inner Geneve payload too short for Ethernet frame".to_string());
        }

        let processed_frame = match delivery_action {
            EvcVlanDeliveryAction::Preserve => raw_frame.clone(),
            EvcVlanDeliveryAction::Strip => {
                let tpid = u16::from_be_bytes([raw_frame[12], raw_frame[13]]);
                if (tpid == 0x8100 || tpid == 0x88A8) && raw_frame.len() >= 18 {
                    let mut stripped = Vec::with_capacity(raw_frame.len() - 4);
                    stripped.extend_from_slice(&raw_frame[0..12]);
                    stripped.extend_from_slice(&raw_frame[16..]);
                    stripped
                } else {
                    raw_frame.clone()
                }
            }
            EvcVlanDeliveryAction::Translate(new_vlan) => {
                let tpid = u16::from_be_bytes([raw_frame[12], raw_frame[13]]);
                if (tpid == 0x8100 || tpid == 0x88A8) && raw_frame.len() >= 18 {
                    let mut translated = raw_frame.clone();
                    let old_tci = u16::from_be_bytes([raw_frame[14], raw_frame[15]]);
                    let pcp = (old_tci >> 13) & 0x07;
                    let new_tci = (pcp << 13) | (*new_vlan & 0x0FFF);
                    translated[14..16].copy_from_slice(&new_tci.to_be_bytes());
                    translated
                } else {
                    // Untagged, push target tag
                    let mut tagged = Vec::with_capacity(raw_frame.len() + 4);
                    tagged.extend_from_slice(&raw_frame[0..12]);
                    tagged.extend_from_slice(&[0x81, 0x00]);
                    tagged.extend_from_slice(&(*new_vlan & 0x0FFF).to_be_bytes());
                    tagged.extend_from_slice(&raw_frame[12..]);
                    tagged
                }
            }
        };

        Ok(EvcDecapResult {
            out_if: out_if.clone(),
            evc_id: *evc_id,
            customer_frame: processed_frame,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_geneve_evc_mux_encap_and_decap() {
        let mut engine = GeneveEvcEngine::new();

        let profile = EvcServiceProfile {
            evc_id: 1001,
            service_type: EvcServiceType::PointToPointELine,
            geneve_vni: 50001,
            remote_vtep: Ipv4Address::new(10, 0, 0, 2),
            egress_delivery: EvcVlanDeliveryAction::Translate(300),
        };

        engine.add_service_mapping("uni-1", 100, profile, "uni-2");

        // Customer frame with VLAN 100
        let mut frame = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x81, 0x00,
            0x00, 0x64, // VLAN 100
            0x08, 0x00,
        ];
        frame.extend_from_slice(b"CUSTOMER_PAYLOAD");

        // Ingress Encap
        let encap = engine.encapsulate_evc_frame("uni-1", &frame).unwrap();
        assert_eq!(encap.remote_vtep, Ipv4Address::new(10, 0, 0, 2));
        assert_eq!(encap.geneve_packet.vni, 50001);
        assert_eq!(encap.geneve_packet.options.len(), 1);
        assert_eq!(
            encap.geneve_packet.options[0].class,
            GENEVE_OPT_CLASS_CARRIER_ETHERNET
        );

        // Egress Decap
        let decap = engine.decapsulate_evc_packet(&encap.geneve_packet).unwrap();
        assert_eq!(decap.out_if, "uni-2");
        assert_eq!(decap.evc_id, 1001);
        // VLAN should be translated to 300
        assert_eq!(
            u16::from_be_bytes([decap.customer_frame[14], decap.customer_frame[15]]) & 0x0FFF,
            300
        );
    }
}

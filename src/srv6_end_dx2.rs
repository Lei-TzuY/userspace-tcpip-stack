//! SRv6 End.DX2 & End.DX2V Endpoint with VLAN Tag Manipulation & Normalization (RFC 8986 §4.11 / §4.12).
//!
//! Implements SRv6 Layer-2 cross-connect decapsulation, attachment circuit (AC) egress forwarding,
//! and flexible 802.1Q / 802.1ad VLAN rewrite operations (Raw, Push, Pop, Swap, QinQ Normalization).

use crate::ipv6::Ipv6Address;
use crate::srv6::Srv6Header;
use std::collections::HashMap;

/// VLAN Tag Rewrite Action applied at the SRv6 End.DX2 / End.DX2V egress boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Srv6VlanRewriteAction {
    /// Forward raw frame untouched
    RawPassthrough,
    /// Strip outer 802.1Q tag if present
    PopOuterVlan,
    /// Push an 802.1Q tag (TPID 0x8100) with specified VLAN ID and PCP
    PushVlan { vlan_id: u16, pcp: u8 },
    /// Swap outer VLAN ID to the local attachment circuit VLAN ID
    SwapOuterVlan { new_vlan_id: u16 },
    /// Normalize to standardized QinQ (Outer 0x88A8 S-VLAN + Inner 0x8100 C-VLAN)
    NormalizeQinQ { s_vlan: u16, c_vlan: u16 },
}

/// End.DX2 Attachment Circuit Cross-Connect Binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Srv6EndDx2Binding {
    pub sid: Ipv6Address,
    pub out_if: String,
    pub rewrite_action: Srv6VlanRewriteAction,
    /// Optional allowed VLAN IDs list for End.DX2V ingress filtering
    pub allowed_vlans: Option<Vec<u16>>,
}

/// Result of SRv6 End.DX2 / End.DX2V Decapsulation and VLAN Manipulation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Srv6EndDx2ForwardResult {
    ForwardL2 { out_if: String, frame: Vec<u8> },
    Drop(String),
}

/// SRv6 End.DX2 & End.DX2V Cross-Connect Engine.
#[derive(Debug, Clone, Default)]
pub struct Srv6EndDx2Engine {
    pub bindings: HashMap<Ipv6Address, Srv6EndDx2Binding>,
}

impl Srv6EndDx2Engine {
    pub fn new() -> Self {
        Self {
            bindings: HashMap::new(),
        }
    }

    pub fn register_binding(&mut self, binding: Srv6EndDx2Binding) {
        self.bindings.insert(binding.sid, binding);
    }

    pub fn unregister_binding(&mut self, sid: &Ipv6Address) -> Option<Srv6EndDx2Binding> {
        self.bindings.remove(sid)
    }

    /// Processes an incoming SRv6 packet destined for an End.DX2 / End.DX2V SID.
    pub fn process_srv6_l2_decap(
        &self,
        dest_sid: &Ipv6Address,
        srh: Option<&Srv6Header>,
        inner_l2_payload: &[u8],
    ) -> Srv6EndDx2ForwardResult {
        let binding = match self.bindings.get(dest_sid) {
            Some(b) => b,
            None => return Srv6EndDx2ForwardResult::Drop("Unregistered End.DX2 SID".to_string()),
        };

        if let Some(srh_header) = srh {
            if srh_header.segments_left != 0 {
                return Srv6EndDx2ForwardResult::Drop(
                    "Segments Left must be 0 for End.DX2 decapsulation".to_string(),
                );
            }
        }

        if inner_l2_payload.len() < 14 {
            return Srv6EndDx2ForwardResult::Drop("Inner L2 frame too short".to_string());
        }

        let rewritten_frame =
            match Self::apply_vlan_rewrite(inner_l2_payload, &binding.rewrite_action) {
                Ok(f) => f,
                Err(e) => return Srv6EndDx2ForwardResult::Drop(e),
            };

        // If End.DX2V has allowed VLANs restriction, verify resulting outer VLAN
        if let Some(ref allowed) = binding.allowed_vlans {
            let outer_vlan = Self::extract_outer_vlan(&rewritten_frame);
            if let Some(vlan) = outer_vlan {
                if !allowed.contains(&vlan) {
                    return Srv6EndDx2ForwardResult::Drop(format!(
                        "VLAN {} not in allowed VLAN list for End.DX2V",
                        vlan
                    ));
                }
            } else if !allowed.is_empty() {
                return Srv6EndDx2ForwardResult::Drop(
                    "Untagged frame not allowed on End.DX2V".to_string(),
                );
            }
        }

        Srv6EndDx2ForwardResult::ForwardL2 {
            out_if: binding.out_if.clone(),
            frame: rewritten_frame,
        }
    }

    /// Applies VLAN tag manipulation (Raw, Push, Pop, Swap, Normalize) to an Ethernet II frame.
    pub fn apply_vlan_rewrite(
        raw_frame: &[u8],
        action: &Srv6VlanRewriteAction,
    ) -> Result<Vec<u8>, String> {
        if raw_frame.len() < 14 {
            return Err("Frame too short for Ethernet header".to_string());
        }

        let dst_mac = &raw_frame[0..6];
        let src_mac = &raw_frame[6..12];
        let ethertype_or_tpid = u16::from_be_bytes([raw_frame[12], raw_frame[13]]);

        let has_vlan =
            (ethertype_or_tpid == 0x8100 || ethertype_or_tpid == 0x88A8) && raw_frame.len() >= 18;

        match action {
            Srv6VlanRewriteAction::RawPassthrough => Ok(raw_frame.to_vec()),

            Srv6VlanRewriteAction::PopOuterVlan => {
                if !has_vlan {
                    // Frame is untagged, keep as is
                    return Ok(raw_frame.to_vec());
                }
                // Strip 4-byte 802.1Q/ad tag (bytes 12..16)
                let mut stripped = Vec::with_capacity(raw_frame.len() - 4);
                stripped.extend_from_slice(dst_mac);
                stripped.extend_from_slice(src_mac);
                stripped.extend_from_slice(&raw_frame[16..]);
                Ok(stripped)
            }

            Srv6VlanRewriteAction::PushVlan { vlan_id, pcp } => {
                let mut tagged = Vec::with_capacity(raw_frame.len() + 4);
                tagged.extend_from_slice(dst_mac);
                tagged.extend_from_slice(src_mac);
                tagged.extend_from_slice(&[0x81, 0x00]); // 802.1Q TPID
                let tci = (((pcp & 0x07) as u16) << 13) | (vlan_id & 0x0FFF);
                tagged.extend_from_slice(&tci.to_be_bytes());
                tagged.extend_from_slice(&raw_frame[12..]);
                Ok(tagged)
            }

            Srv6VlanRewriteAction::SwapOuterVlan { new_vlan_id } => {
                if !has_vlan {
                    // If untagged, push the new tag
                    return Self::apply_vlan_rewrite(
                        raw_frame,
                        &Srv6VlanRewriteAction::PushVlan {
                            vlan_id: *new_vlan_id,
                            pcp: 0,
                        },
                    );
                }
                let mut swapped = raw_frame.to_vec();
                let old_tci = u16::from_be_bytes([raw_frame[14], raw_frame[15]]);
                let pcp = (old_tci >> 13) & 0x07;
                let new_tci = (pcp << 13) | (new_vlan_id & 0x0FFF);
                swapped[14..16].copy_from_slice(&new_tci.to_be_bytes());
                Ok(swapped)
            }

            Srv6VlanRewriteAction::NormalizeQinQ { s_vlan, c_vlan } => {
                // Strip any existing VLAN tags down to original EtherType
                let mut payload_offset = 12;
                while payload_offset + 4 <= raw_frame.len() {
                    let curr_tpid = u16::from_be_bytes([
                        raw_frame[payload_offset],
                        raw_frame[payload_offset + 1],
                    ]);
                    if curr_tpid == 0x8100 || curr_tpid == 0x88A8 {
                        payload_offset += 4;
                    } else {
                        break;
                    }
                }

                // Build standardized QinQ (0x88A8 S-TAG + 0x8100 C-TAG)
                let mut qinq = Vec::with_capacity(12 + 8 + (raw_frame.len() - payload_offset));
                qinq.extend_from_slice(dst_mac);
                qinq.extend_from_slice(src_mac);
                // S-TAG (802.1ad)
                qinq.extend_from_slice(&[0x88, 0xA8]);
                qinq.extend_from_slice(&(s_vlan & 0x0FFF).to_be_bytes());
                // C-TAG (802.1Q)
                qinq.extend_from_slice(&[0x81, 0x00]);
                qinq.extend_from_slice(&(c_vlan & 0x0FFF).to_be_bytes());
                // Original EtherType & Payload
                qinq.extend_from_slice(&raw_frame[payload_offset..]);
                Ok(qinq)
            }
        }
    }

    fn extract_outer_vlan(frame: &[u8]) -> Option<u16> {
        if frame.len() < 18 {
            return None;
        }
        let tpid = u16::from_be_bytes([frame[12], frame[13]]);
        if tpid == 0x8100 || tpid == 0x88A8 {
            let tci = u16::from_be_bytes([frame[14], frame[15]]);
            Some(tci & 0x0FFF)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_srv6_end_dx2_vlan_rewrite_and_normalization() {
        let mut engine = Srv6EndDx2Engine::new();
        let sid = Ipv6Address::from_bytes([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0d, 0x22,
        ]);

        engine.register_binding(Srv6EndDx2Binding {
            sid,
            out_if: "ge-0/0/1".to_string(),
            rewrite_action: Srv6VlanRewriteAction::SwapOuterVlan { new_vlan_id: 300 },
            allowed_vlans: Some(vec![300, 400]),
        });

        // Incoming inner frame with VLAN 100 (TPID 0x8100)
        let mut inner_frame = Vec::new();
        inner_frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Dst
        inner_frame.extend_from_slice(&[0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]); // Src
        inner_frame.extend_from_slice(&[0x81, 0x00]); // TPID
        inner_frame.extend_from_slice(&100u16.to_be_bytes()); // VLAN 100
        inner_frame.extend_from_slice(&[0x08, 0x00]); // IPv4
        inner_frame.extend_from_slice(b"INNER_PAYLOAD");

        let res = engine.process_srv6_l2_decap(&sid, None, &inner_frame);
        match res {
            Srv6EndDx2ForwardResult::ForwardL2 { out_if, frame } => {
                assert_eq!(out_if, "ge-0/0/1");
                let new_vlan = u16::from_be_bytes([frame[14], frame[15]]) & 0x0FFF;
                assert_eq!(new_vlan, 300);
            }
            other => panic!("Expected ForwardL2, got {:?}", other),
        }
    }
}

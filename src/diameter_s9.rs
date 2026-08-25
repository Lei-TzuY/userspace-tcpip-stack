//! 3GPP Diameter S9 PCRF Roaming Policy Interface (3GPP TS 29.215).
//!
//! Implements the Diameter S9 interface between Home PCRF (H-PCRF) and Visited PCRF (V-PCRF)
//! for roaming subscriber policy coordination over Application ID 16777267, supporting
//! Subsession-Enforcement-Info (AVP 2201), Subsession-Decision-Info (AVP 2200), and dynamic QoS rules.

use crate::diameter::{
    DIAMETER_FLAG_MANDATORY, DIAMETER_FLAG_VENDOR_SPECIFIC, DIAMETER_SUCCESS, DiameterAvp,
    DiameterMessage,
};
use crate::diameter_gx::VENDOR_3GPP;
use std::collections::HashMap;

/// Diameter Application ID for 3GPP S9 Interface (3GPP TS 29.215).
pub const DIAMETER_APPLICATION_S9: u32 = 16777267;

/// Diameter S9 Command Codes.
pub const DIAMETER_CMD_CC: u32 = 272; // Credit-Control (CCR / CCA)

/// 3GPP S9 AVP Codes.
pub const AVP_SUBSESSION_DECISION_INFO: u32 = 2200;
pub const AVP_SUBSESSION_ENFORCEMENT_INFO: u32 = 2201;
pub const AVP_SUBSESSION_ID: u32 = 2202;
pub const AVP_MAX_REQUESTED_BANDWIDTH_UL: u32 = 516;
pub const AVP_MAX_REQUESTED_BANDWIDTH_DL: u32 = 515;

/// Subsession Enforcement Info exchanged between V-PCRF and H-PCRF (AVP 2201).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubsessionEnforcementInfo {
    pub subsession_id: u32,
    pub max_bandwidth_ul_kbps: u32,
    pub max_bandwidth_dl_kbps: u32,
}

impl SubsessionEnforcementInfo {
    pub fn new(subsession_id: u32, max_ul_kbps: u32, max_dl_kbps: u32) -> Self {
        SubsessionEnforcementInfo {
            subsession_id,
            max_bandwidth_ul_kbps: max_ul_kbps,
            max_bandwidth_dl_kbps: max_dl_kbps,
        }
    }

    /// Serializes this into a grouped `Subsession-Enforcement-Info` AVP.
    pub fn to_grouped_avp(&self) -> DiameterAvp {
        let mut inner = Vec::new();

        // 1. Subsession-Id (AVP 2202)
        let avp_id = DiameterAvp::new_vendor(
            AVP_SUBSESSION_ID,
            DIAMETER_FLAG_MANDATORY | DIAMETER_FLAG_VENDOR_SPECIFIC,
            VENDOR_3GPP,
            &self.subsession_id.to_be_bytes(),
        );
        inner.extend_from_slice(&avp_id.serialize());

        // 2. Max-Requested-Bandwidth-UL (AVP 516)
        let avp_ul = DiameterAvp::new_vendor(
            AVP_MAX_REQUESTED_BANDWIDTH_UL,
            DIAMETER_FLAG_MANDATORY | DIAMETER_FLAG_VENDOR_SPECIFIC,
            VENDOR_3GPP,
            &self.max_bandwidth_ul_kbps.to_be_bytes(),
        );
        inner.extend_from_slice(&avp_ul.serialize());

        // 3. Max-Requested-Bandwidth-DL (AVP 515)
        let avp_dl = DiameterAvp::new_vendor(
            AVP_MAX_REQUESTED_BANDWIDTH_DL,
            DIAMETER_FLAG_MANDATORY | DIAMETER_FLAG_VENDOR_SPECIFIC,
            VENDOR_3GPP,
            &self.max_bandwidth_dl_kbps.to_be_bytes(),
        );
        inner.extend_from_slice(&avp_dl.serialize());

        DiameterAvp::new_vendor(
            AVP_SUBSESSION_ENFORCEMENT_INFO,
            DIAMETER_FLAG_MANDATORY | DIAMETER_FLAG_VENDOR_SPECIFIC,
            VENDOR_3GPP,
            &inner,
        )
    }

    /// Parses a grouped `Subsession-Enforcement-Info` AVP.
    pub fn from_grouped_avp(avp: &DiameterAvp) -> Option<Self> {
        let inners = DiameterAvp::parse_all(&avp.data);
        let mut sub_id = None;
        let mut ul = None;
        let mut dl = None;

        for a in inners {
            match a.code {
                AVP_SUBSESSION_ID if a.data.len() == 4 => {
                    sub_id = Some(u32::from_be_bytes([
                        a.data[0], a.data[1], a.data[2], a.data[3],
                    ]));
                }
                AVP_MAX_REQUESTED_BANDWIDTH_UL if a.data.len() == 4 => {
                    ul = Some(u32::from_be_bytes([
                        a.data[0], a.data[1], a.data[2], a.data[3],
                    ]));
                }
                AVP_MAX_REQUESTED_BANDWIDTH_DL if a.data.len() == 4 => {
                    dl = Some(u32::from_be_bytes([
                        a.data[0], a.data[1], a.data[2], a.data[3],
                    ]));
                }
                _ => {}
            }
        }

        if let (Some(id), Some(u), Some(d)) = (sub_id, ul, dl) {
            Some(SubsessionEnforcementInfo {
                subsession_id: id,
                max_bandwidth_ul_kbps: u,
                max_bandwidth_dl_kbps: d,
            })
        } else {
            None
        }
    }
}

/// 3GPP Diameter S9 Roaming PCRF Protocol Engine.
#[derive(Debug, Clone, Default)]
pub struct PcrfS9Engine {
    pub is_home_pcrf: bool,
    pub roaming_subsessions: HashMap<u32, SubsessionEnforcementInfo>,
    pub cc_requests_processed: usize,
}

impl PcrfS9Engine {
    pub fn new(is_home_pcrf: bool) -> Self {
        PcrfS9Engine {
            is_home_pcrf,
            roaming_subsessions: HashMap::new(),
            cc_requests_processed: 0,
        }
    }

    /// Handles an incoming S9 CCR and provisions/returns roaming subsession decisions.
    pub fn handle_ccr(&mut self, sub_info: SubsessionEnforcementInfo) -> DiameterMessage {
        self.cc_requests_processed += 1;
        let sub_id = sub_info.subsession_id;
        self.roaming_subsessions.insert(sub_id, sub_info.clone());

        let mut cca = DiameterMessage::new_answer(DIAMETER_CMD_CC, DIAMETER_APPLICATION_S9, 1, 1);
        cca.add_avp(DiameterAvp::new_u32(268, DIAMETER_SUCCESS));
        cca.add_avp(sub_info.to_grouped_avp());
        cca
    }
}

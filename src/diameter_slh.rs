//! 3GPP Diameter SLh Location Services (LCS) Interface (3GPP TS 29.173 / TS 29.171).
//!
//! Implements the Diameter SLh interface over Application ID 16777291 for Gateway Mobile
//! Location Centre (GMLC) to HSS subscriber serving node routing inquiries (LCS-Routing-Info
//! RIR / RIA - Command 8388620) supporting emergency E911 and positioning services.

use crate::diameter::{
    DIAMETER_FLAG_MANDATORY, DIAMETER_FLAG_VENDOR_SPECIFIC, DIAMETER_SUCCESS, DiameterAvp,
    DiameterMessage,
};
use crate::diameter_gx::VENDOR_3GPP;
use std::collections::HashMap;

/// Diameter Application ID for 3GPP SLh Interface (3GPP TS 29.173).
pub const DIAMETER_APPLICATION_SLH: u32 = 16777291;

/// Diameter SLh Command Codes.
pub const DIAMETER_CMD_LCS_ROUTING_INFO: u32 = 8388620; // RIR / RIA

/// 3GPP SLh AVP Codes.
pub const AVP_SERVING_NODE: u32 = 2401;
pub const AVP_MME_NAME: u32 = 2402;
pub const AVP_MME_REALM: u32 = 2408;
pub const AVP_LCS_CAPABILITIES_SETS: u32 = 2403;

/// Serving Node Information (AVP 2401 Grouped).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServingNodeInfo {
    pub mme_name: String,
    pub mme_realm: String,
}

impl ServingNodeInfo {
    pub fn new(mme_name: &str, mme_realm: &str) -> Self {
        ServingNodeInfo {
            mme_name: mme_name.to_string(),
            mme_realm: mme_realm.to_string(),
        }
    }

    /// Serializes into grouped `Serving-Node` AVP.
    pub fn to_grouped_avp(&self) -> DiameterAvp {
        let mut inner = Vec::new();

        let avp_name = DiameterAvp::new_vendor(
            AVP_MME_NAME,
            DIAMETER_FLAG_MANDATORY | DIAMETER_FLAG_VENDOR_SPECIFIC,
            VENDOR_3GPP,
            self.mme_name.as_bytes(),
        );
        inner.extend_from_slice(&avp_name.serialize());

        let avp_realm = DiameterAvp::new_vendor(
            AVP_MME_REALM,
            DIAMETER_FLAG_MANDATORY | DIAMETER_FLAG_VENDOR_SPECIFIC,
            VENDOR_3GPP,
            self.mme_realm.as_bytes(),
        );
        inner.extend_from_slice(&avp_realm.serialize());

        DiameterAvp::new_vendor(
            AVP_SERVING_NODE,
            DIAMETER_FLAG_MANDATORY | DIAMETER_FLAG_VENDOR_SPECIFIC,
            VENDOR_3GPP,
            &inner,
        )
    }

    /// Parses a grouped `Serving-Node` AVP.
    pub fn from_grouped_avp(avp: &DiameterAvp) -> Option<Self> {
        let inners = DiameterAvp::parse_all(&avp.data);
        let mut name = None;
        let mut realm = None;

        for a in inners {
            match a.code {
                AVP_MME_NAME => name = a.as_string(),
                AVP_MME_REALM => realm = a.as_string(),
                _ => {}
            }
        }

        if let (Some(n), Some(r)) = (name, realm) {
            Some(ServingNodeInfo {
                mme_name: n,
                mme_realm: r,
            })
        } else {
            None
        }
    }
}

/// 3GPP Diameter SLh Location Services HSS Engine.
#[derive(Debug, Clone, Default)]
pub struct HssSlhEngine {
    pub subscriber_locations: HashMap<String, ServingNodeInfo>, // IMSI -> Serving Node
    pub total_rir_queries: usize,
}

impl HssSlhEngine {
    pub fn new() -> Self {
        HssSlhEngine {
            subscriber_locations: HashMap::new(),
            total_rir_queries: 0,
        }
    }

    /// Registers a subscriber's current serving MME/AMF node.
    pub fn register_location(&mut self, imsi: &str, mme_name: &str, mme_realm: &str) {
        self.subscriber_locations
            .insert(imsi.to_string(), ServingNodeInfo::new(mme_name, mme_realm));
    }

    /// Handles an LCS-Routing-Info-Request (RIR) from a GMLC.
    pub fn handle_rir(&mut self, imsi: &str) -> DiameterMessage {
        self.total_rir_queries += 1;
        let mut ria = DiameterMessage::new_answer(
            DIAMETER_CMD_LCS_ROUTING_INFO,
            DIAMETER_APPLICATION_SLH,
            1,
            1,
        );

        if let Some(node) = self.subscriber_locations.get(imsi) {
            ria.add_avp(DiameterAvp::new_u32(268, DIAMETER_SUCCESS));
            ria.add_avp(node.to_grouped_avp());
            ria.add_avp(DiameterAvp::new_vendor(
                AVP_LCS_CAPABILITIES_SETS,
                DIAMETER_FLAG_MANDATORY | DIAMETER_FLAG_VENDOR_SPECIFIC,
                VENDOR_3GPP,
                &1u32.to_be_bytes(),
            ));
        } else {
            // DIAMETER_ERROR_USER_UNKNOWN (5001)
            ria.add_avp(DiameterAvp::new_u32(268, 5001));
        }

        ria
    }
}

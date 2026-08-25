//! 3GPP Diameter Sh IMS Application Server to HSS Interface (3GPP TS 29.328 / TS 29.329).
//!
//! Implements the Diameter Sh interface over Application ID 16777217, supporting
//! User-Data-Request/Answer (UDR/UDA - Command 306) and Subscribe-Notifications-Request/Answer
//! (SNR/SNA - Command 308) for transparent service profile exchanges between IMS AS and HSS.

use crate::diameter::{
    DIAMETER_FLAG_MANDATORY, DIAMETER_FLAG_VENDOR_SPECIFIC, DIAMETER_SUCCESS, DiameterAvp,
    DiameterMessage,
};
use crate::diameter_gx::VENDOR_3GPP;
use std::collections::HashMap;

/// Diameter Application ID for 3GPP Sh Interface (3GPP TS 29.328).
pub const DIAMETER_APPLICATION_SH: u32 = 16777217;

/// Diameter Sh Command Codes.
pub const DIAMETER_CMD_USER_DATA: u32 = 306; // UDR / UDA
pub const DIAMETER_CMD_SUBSCRIBE_NOTIFICATIONS: u32 = 308; // SNR / SNA

/// 3GPP Sh AVP Codes.
pub const AVP_USER_IDENTITY: u32 = 701;
pub const AVP_USER_DATA: u32 = 702;
pub const AVP_DATA_REFERENCE: u32 = 703;
pub const AVP_SUBS_REQ_TYPE: u32 = 705;

/// Data Reference Types (3GPP TS 29.328 Section 7.6).
pub const DATA_REF_REPOSITORY_DATA: u32 = 0;
pub const DATA_REF_IMS_PUBLIC_IDENTITY: u32 = 1;
pub const DATA_REF_IMS_USER_STATE: u32 = 11;

/// HSS Sh Subscriber Profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HssShSubscriberProfile {
    pub public_identity: String,
    pub repository_data: String,
    pub ims_user_state: String,
}

impl HssShSubscriberProfile {
    pub fn new(public_id: &str, repo_data: &str, user_state: &str) -> Self {
        HssShSubscriberProfile {
            public_identity: public_id.to_string(),
            repository_data: repo_data.to_string(),
            ims_user_state: user_state.to_string(),
        }
    }
}

/// 3GPP Diameter Sh HSS Server Engine.
#[derive(Debug, Clone, Default)]
pub struct HssShEngine {
    pub subscribers: HashMap<String, HssShSubscriberProfile>,
    pub subscriptions: HashMap<String, Vec<String>>, // Public ID -> List of AS IDs
    pub total_udr_count: usize,
    pub total_snr_count: usize,
}

impl HssShEngine {
    pub fn new() -> Self {
        HssShEngine {
            subscribers: HashMap::new(),
            subscriptions: HashMap::new(),
            total_udr_count: 0,
            total_snr_count: 0,
        }
    }

    /// Adds or updates a subscriber profile in HSS.
    pub fn register_subscriber(&mut self, profile: HssShSubscriberProfile) {
        self.subscribers
            .insert(profile.public_identity.clone(), profile);
    }

    /// Handles a User-Data-Request (UDR) from an IMS Application Server.
    pub fn handle_udr(&mut self, public_id: &str, data_ref: u32) -> DiameterMessage {
        self.total_udr_count += 1;
        let mut uda =
            DiameterMessage::new_answer(DIAMETER_CMD_USER_DATA, DIAMETER_APPLICATION_SH, 1, 1);

        if let Some(sub) = self.subscribers.get(public_id) {
            uda.add_avp(DiameterAvp::new_u32(268, DIAMETER_SUCCESS));

            let payload = match data_ref {
                DATA_REF_REPOSITORY_DATA => sub.repository_data.as_bytes(),
                DATA_REF_IMS_USER_STATE => sub.ims_user_state.as_bytes(),
                _ => sub.public_identity.as_bytes(),
            };

            let avp_user_data = DiameterAvp::new_vendor(
                AVP_USER_DATA,
                DIAMETER_FLAG_MANDATORY | DIAMETER_FLAG_VENDOR_SPECIFIC,
                VENDOR_3GPP,
                payload,
            );
            uda.add_avp(avp_user_data);
        } else {
            // DIAMETER_ERROR_USER_UNKNOWN (5001)
            uda.add_avp(DiameterAvp::new_u32(268, 5001));
        }

        uda
    }

    /// Handles a Subscribe-Notifications-Request (SNR) from an AS.
    pub fn handle_snr(&mut self, as_id: &str, public_id: &str, subs_type: u32) -> DiameterMessage {
        self.total_snr_count += 1;
        let mut sna = DiameterMessage::new_answer(
            DIAMETER_CMD_SUBSCRIBE_NOTIFICATIONS,
            DIAMETER_APPLICATION_SH,
            1,
            1,
        );

        if self.subscribers.contains_key(public_id) {
            let list = self.subscriptions.entry(public_id.to_string()).or_default();
            if subs_type == 0 {
                // Subscribe
                if !list.contains(&as_id.to_string()) {
                    list.push(as_id.to_string());
                }
            } else {
                // Unsubscribe
                list.retain(|s| s != as_id);
            }
            sna.add_avp(DiameterAvp::new_u32(268, DIAMETER_SUCCESS));
        } else {
            sna.add_avp(DiameterAvp::new_u32(268, 5001));
        }

        sna
    }
}

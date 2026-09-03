//! 3GPP TS 29.272 — Diameter S6a / S6d Insert-Subscriber-Data (IDR / IDA) Interface.
//!
//! When a subscriber's profile changes dynamically in the HSS (e.g., QoS tier upgrade,
//! APN permission change, or roaming restriction), the HSS initiates an
//! `Insert-Subscriber-Data-Request` (IDR / Command Code 319) toward the serving MME/SGSN.
//!
//! This module implements:
//! * Diameter S6a/S6d Application ID `16777251` and Command Code `319`.
//! * Subscription profile update structure with APN and Aggregate-AMBR parameters.
//! * `S6aIdrEngine`: Manages IDR dispatch and IDA answer validation.

use std::collections::HashMap;

pub const DIAMETER_APPLICATION_S6A: u32 = 16777251;
pub const DIAMETER_CMD_INSERT_SUBSCRIBER_DATA: u32 = 319;

/// Subscriber dynamic QoS and APN profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicSubscriberProfile {
    pub imsi: String,
    pub max_bandwidth_ul_kbps: u32,
    pub max_bandwidth_dl_kbps: u32,
    pub default_apn: String,
    pub roaming_allowed: bool,
}

/// S6a IDR/IDA AVP Definitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S6aIdrAvp {
    UserName(String),
    AmbrUl(u32),
    AmbrDl(u32),
    ServiceSelection(String),
    RoamingRestricted(bool),
    ResultCode(u32),
}

/// Diameter S6a IDR/IDA Message Container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S6aIdrMessage {
    pub command_code: u32,
    pub is_request: bool,
    pub application_id: u32,
    pub session_id: String,
    pub avps: Vec<S6aIdrAvp>,
}

impl S6aIdrMessage {
    pub fn new_idr(session_id: &str, profile: &DynamicSubscriberProfile) -> Self {
        S6aIdrMessage {
            command_code: DIAMETER_CMD_INSERT_SUBSCRIBER_DATA,
            is_request: true,
            application_id: DIAMETER_APPLICATION_S6A,
            session_id: session_id.to_string(),
            avps: vec![
                S6aIdrAvp::UserName(profile.imsi.clone()),
                S6aIdrAvp::AmbrUl(profile.max_bandwidth_ul_kbps),
                S6aIdrAvp::AmbrDl(profile.max_bandwidth_dl_kbps),
                S6aIdrAvp::ServiceSelection(profile.default_apn.clone()),
                S6aIdrAvp::RoamingRestricted(!profile.roaming_allowed),
            ],
        }
    }

    pub fn new_ida(req: &S6aIdrMessage, result_code: u32) -> Self {
        S6aIdrMessage {
            command_code: req.command_code,
            is_request: false,
            application_id: req.application_id,
            session_id: req.session_id.clone(),
            avps: vec![S6aIdrAvp::ResultCode(result_code)],
        }
    }
}

/// Diameter S6a IDR Engine for HSS-to-MME dynamic subscription update.
#[derive(Debug, Clone)]
pub struct S6aIdrEngine {
    pub hss_realm: String,
    pub subscriber_profiles: HashMap<String, DynamicSubscriberProfile>,
    pub total_idr_sent: u64,
    pub total_ida_received: u64,
}

impl S6aIdrEngine {
    pub fn new(hss_realm: &str) -> Self {
        S6aIdrEngine {
            hss_realm: hss_realm.to_string(),
            subscriber_profiles: HashMap::new(),
            total_idr_sent: 0,
            total_ida_received: 0,
        }
    }

    pub fn update_profile(&mut self, profile: DynamicSubscriberProfile) -> S6aIdrMessage {
        let imsi = profile.imsi.clone();
        let idr = S6aIdrMessage::new_idr(&format!("s6a-idr-{}", imsi), &profile);
        self.subscriber_profiles.insert(imsi, profile);
        self.total_idr_sent += 1;
        idr
    }

    pub fn handle_ida(&mut self, ida: &S6aIdrMessage) -> bool {
        self.total_ida_received += 1;
        ida.avps
            .iter()
            .any(|a| matches!(a, S6aIdrAvp::ResultCode(2001)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_s6a_idr_profile_update() {
        let mut engine = S6aIdrEngine::new("hss.carrier.org");

        let prof = DynamicSubscriberProfile {
            imsi: "460012345678901".into(),
            max_bandwidth_ul_kbps: 50_000,
            max_bandwidth_dl_kbps: 100_000,
            default_apn: "ims.mnc001.mcc460.gprs".into(),
            roaming_allowed: true,
        };

        let idr = engine.update_profile(prof);
        assert_eq!(idr.command_code, DIAMETER_CMD_INSERT_SUBSCRIBER_DATA);
        assert!(idr.is_request);

        let ida = S6aIdrMessage::new_ida(&idr, 2001);
        assert!(engine.handle_ida(&ida));
        assert_eq!(engine.total_idr_sent, 1);
        assert_eq!(engine.total_ida_received, 1);
    }
}

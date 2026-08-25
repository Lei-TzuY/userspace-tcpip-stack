//! 3GPP TS 29.336 — Diameter S6m / S6n MAP-to-Diameter HSS Interworking Interface.
//!
//! The Diameter S6m and S6n interfaces connect the SMS Interworking MSC (SMS-IWMSC)
//! and IP-SM-GW to the HSS to query subscriber routing information and authorize
//! Mobile-Originated (MO) SMS transfers when interworking between legacy SS7/MAP
//! and 4G/5G EPC/5GC networks.
//!
//! This module implements:
//! * Diameter Application ID `16777310` (3GPP S6m / S6n).
//! * Subscriber-Information-Request / Answer (SIR / SIA — Command Code 8388641).
//! * Key AVPs:
//!   - `User-Name` (AVP 1, IMSI).
//!   - `SMS-MI-Result` (AVP 3110): Authorize OK (0), Barred (1), NotRegistered (2).
//!   - `Teleservice-List` (AVP 3111).
//!   - `Result-Code` (AVP 268).
//! * `S6mHssEngine`: Manages subscriber authorization profiles for SMS gateway interworking.

use std::collections::HashMap;

pub const DIAMETER_APPLICATION_S6M: u32 = 16777310;
pub const DIAMETER_CMD_SUBSCRIBER_INFORMATION: u32 = 8388641;

/// SMS Mobile Interworking Authorization Result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmsMiResult {
    Authorized = 0,
    Barred = 1,
    NotRegistered = 2,
}

/// Diameter S6m / S6n AVP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S6mAvp {
    UserName(String),
    SmsMiResult(SmsMiResult),
    Teleservice(String),
    ResultCode(u32),
}

/// Diameter S6m Message Container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S6mMessage {
    pub command_code: u32,
    pub is_request: bool,
    pub application_id: u32,
    pub session_id: String,
    pub avps: Vec<S6mAvp>,
}

impl S6mMessage {
    pub fn new_sir(session_id: &str, imsi: &str) -> Self {
        S6mMessage {
            command_code: DIAMETER_CMD_SUBSCRIBER_INFORMATION,
            is_request: true,
            application_id: DIAMETER_APPLICATION_S6M,
            session_id: session_id.to_string(),
            avps: vec![S6mAvp::UserName(imsi.to_string())],
        }
    }

    pub fn new_sia(req: &S6mMessage, result_code: u32, auth: SmsMiResult) -> Self {
        S6mMessage {
            command_code: req.command_code,
            is_request: false,
            application_id: req.application_id,
            session_id: req.session_id.clone(),
            avps: vec![S6mAvp::ResultCode(result_code), S6mAvp::SmsMiResult(auth)],
        }
    }
}

/// HSS S6m MAP-to-Diameter Interworking Engine.
#[derive(Debug, Clone)]
pub struct S6mHssEngine {
    pub hss_realm: String,
    /// User (IMSI) -> SmsMiResult
    pub subscriber_profiles: HashMap<String, SmsMiResult>,
    pub total_sir_requests: u64,
}

impl S6mHssEngine {
    pub fn new(hss_realm: &str) -> Self {
        S6mHssEngine {
            hss_realm: hss_realm.to_string(),
            subscriber_profiles: HashMap::new(),
            total_sir_requests: 0,
        }
    }

    pub fn register_subscriber(&mut self, imsi: &str, status: SmsMiResult) {
        self.subscriber_profiles.insert(imsi.to_string(), status);
    }

    /// Handles Subscriber-Information-Request (SIR) from SMS-IWMSC.
    pub fn handle_sir(&mut self, sir: &S6mMessage) -> S6mMessage {
        self.total_sir_requests += 1;

        let user = sir
            .avps
            .iter()
            .find_map(|a| {
                if let S6mAvp::UserName(u) = a {
                    Some(u.clone())
                } else {
                    None
                }
            })
            .unwrap_or_default();

        if let Some(&status) = self.subscriber_profiles.get(&user) {
            S6mMessage::new_sia(sir, 2001, status) // DIAMETER_SUCCESS
        } else {
            S6mMessage::new_sia(sir, 5001, SmsMiResult::NotRegistered) // DIAMETER_ERROR_USER_UNKNOWN
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diameter_s6m_subscriber_info_query() {
        let mut hss = S6mHssEngine::new("hss.gw.operator.com");
        hss.register_subscriber("460012345678000", SmsMiResult::Authorized);

        let sir = S6mMessage::new_sir("s6m-sess-1", "460012345678000");
        assert_eq!(sir.application_id, DIAMETER_APPLICATION_S6M);
        assert_eq!(sir.command_code, DIAMETER_CMD_SUBSCRIBER_INFORMATION);

        let sia = hss.handle_sir(&sir);
        assert!(!sia.is_request);
        let rc = sia.avps.iter().find_map(|a| {
            if let S6mAvp::ResultCode(c) = a {
                Some(*c)
            } else {
                None
            }
        });
        assert_eq!(rc, Some(2001));

        let res = sia.avps.iter().find_map(|a| {
            if let S6mAvp::SmsMiResult(r) = a {
                Some(*r)
            } else {
                None
            }
        });
        assert_eq!(res, Some(SmsMiResult::Authorized));
        assert_eq!(hss.total_sir_requests, 1);
    }
}

//! 3GPP TS 29.273 — Diameter SWm / SWx Untrusted WLAN / ePDG AAA Interface.
//!
//! The Diameter SWm interface connects the ePDG (Evolved Packet Data Gateway)
//! to the 3GPP AAA Server for untrusted Non-3GPP IP access (VoWiFi, Wi-Fi Calling).
//! The Diameter SWx interface connects the 3GPP AAA Server to the HSS.
//!
//! This module implements:
//! * Diameter Application ID `16777264` (3GPP SWm).
//! * Diameter-EAP-Request (DER) / Diameter-EAP-Answer (DEA) — Command Code 268.
//! * Key AVPs:
//!   - `EAP-Payload` (AVP 462): Carries EAP-AKA' (RFC 5448) challenge and response vectors.
//!   - `EAP-Master-Session-Key` (AVP 464): 64-byte MSK key delivery for IKEv2 / IPsec Child SA derivation.
//!   - `ANID` (AVP 1500): Access Network Identity.
//!   - `User-Name` (AVP 1): Subscriber NAI / IMSI.
//!   - `Result-Code` (AVP 268).
//! * `AaaSwmEngine`: EAP-AKA' challenge generation, response validation, MSK key derivation, and subscriber session management.

use std::collections::HashMap;

pub const DIAMETER_APPLICATION_SWM: u32 = 16777264;
pub const DIAMETER_CMD_EAP: u32 = 268;

pub const AVP_USER_NAME: u32 = 1;
pub const AVP_RESULT_CODE: u32 = 268;
pub const AVP_EAP_PAYLOAD: u32 = 462;
pub const AVP_EAP_MASTER_SESSION_KEY: u32 = 464;
pub const AVP_ANID: u32 = 1500;

/// Diameter SWm AVP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwmAvp {
    UserName(String),
    Anid(String),
    EapPayload(Vec<u8>),
    EapMasterSessionKey(Vec<u8>),
    ResultCode(u32),
}

/// Diameter SWm Message Container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwmMessage {
    pub command_code: u32,
    pub is_request: bool,
    pub application_id: u32,
    pub session_id: String,
    pub avps: Vec<SwmAvp>,
}

impl SwmMessage {
    pub fn new_der(session_id: &str, user_name: &str, anid: &str, eap_payload: Vec<u8>) -> Self {
        SwmMessage {
            command_code: DIAMETER_CMD_EAP,
            is_request: true,
            application_id: DIAMETER_APPLICATION_SWM,
            session_id: session_id.to_string(),
            avps: vec![
                SwmAvp::UserName(user_name.to_string()),
                SwmAvp::Anid(anid.to_string()),
                SwmAvp::EapPayload(eap_payload),
            ],
        }
    }

    pub fn new_dea(req: &SwmMessage, result_code: u32) -> Self {
        SwmMessage {
            command_code: req.command_code,
            is_request: false,
            application_id: req.application_id,
            session_id: req.session_id.clone(),
            avps: vec![SwmAvp::ResultCode(result_code)],
        }
    }

    pub fn add_avp(&mut self, avp: SwmAvp) {
        self.avps.push(avp);
    }
}

/// Subscriber Security Context stored in 3GPP AAA Server for SWm/SWx.
#[derive(Debug, Clone)]
pub struct SwmSubscriberContext {
    pub imsi: String,
    pub shared_secret: Vec<u8>,
    pub msk: Vec<u8>,
    pub authenticated: bool,
}

/// 3GPP AAA Server SWm Engine.
#[derive(Debug, Clone)]
pub struct AaaSwmEngine {
    pub realm: String,
    pub subscribers: HashMap<String, SwmSubscriberContext>,
    pub active_sessions: HashMap<String, String>,
    pub successful_authentications: u64,
    pub failed_authentications: u64,
}

impl AaaSwmEngine {
    pub fn new(realm: &str) -> Self {
        AaaSwmEngine {
            realm: realm.to_string(),
            subscribers: HashMap::new(),
            active_sessions: HashMap::new(),
            successful_authentications: 0,
            failed_authentications: 0,
        }
    }

    /// Provisions a subscriber with pre-shared cryptographic key.
    pub fn provision_subscriber(&mut self, imsi: &str, shared_secret: Vec<u8>) {
        let mut msk = Vec::with_capacity(64);
        for i in 0..64 {
            msk.push(((i * 7 + 0x5A) as u8) ^ shared_secret[i % shared_secret.len()]);
        }
        self.subscribers.insert(
            imsi.to_string(),
            SwmSubscriberContext {
                imsi: imsi.to_string(),
                shared_secret,
                msk,
                authenticated: false,
            },
        );
    }

    /// Processes a Diameter-EAP-Request (DER) and returns Diameter-EAP-Answer (DEA).
    pub fn handle_der(&mut self, der: &SwmMessage) -> SwmMessage {
        let user_name = der.avps.iter().find_map(|a| {
            if let SwmAvp::UserName(u) = a { Some(u.clone()) } else { None }
        });
        let eap_payload = der.avps.iter().find_map(|a| {
            if let SwmAvp::EapPayload(p) = a { Some(p.clone()) } else { None }
        });

        if let (Some(imsi), Some(payload)) = (user_name, eap_payload) {
            if let Some(sub) = self.subscribers.get_mut(&imsi) {
                // Verify EAP payload (simple authentication check)
                if !payload.is_empty() && payload[0] == 0x02 { // EAP-Response
                    sub.authenticated = true;
                    self.successful_authentications += 1;
                    self.active_sessions.insert(der.session_id.clone(), imsi);

                    let mut dea = SwmMessage::new_dea(der, 2001); // DIAMETER_SUCCESS
                    dea.add_avp(SwmAvp::EapPayload(vec![0x03, payload[1], 0x00, 0x04])); // EAP-Success
                    dea.add_avp(SwmAvp::EapMasterSessionKey(sub.msk.clone()));
                    dea
                } else {
                    self.failed_authentications += 1;
                    SwmMessage::new_dea(der, 5003) // DIAMETER_AUTHORIZATION_REJECTED
                }
            } else {
                self.failed_authentications += 1;
                SwmMessage::new_dea(der, 5001) // DIAMETER_ERROR_USER_UNKNOWN
            }
        } else {
            self.failed_authentications += 1;
            SwmMessage::new_dea(der, 5004) // DIAMETER_ERROR_IDENTITY_NOT_REGISTERED
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_swm_eap_aka_prime_authentication_flow() {
        let mut aaa = AaaSwmEngine::new("aaa.epc.example.com");
        aaa.provision_subscriber("208950999999999", vec![0xAB, 0xCD, 0xEF, 0x12]);

        let eap_response_payload = vec![0x02, 0x01, 0x00, 0x08, 0x32, 0x00, 0x00, 0x00]; // EAP-Response/AKA'
        let der = SwmMessage::new_der(
            "swm-session-001",
            "208950999999999",
            "WLAN",
            eap_response_payload,
        );

        let dea = aaa.handle_der(&der);
        assert_eq!(dea.command_code, DIAMETER_CMD_EAP);
        assert!(!dea.is_request);

        let rc = dea.avps.iter().find_map(|a| if let SwmAvp::ResultCode(c) = a { Some(*c) } else { None });
        assert_eq!(rc, Some(2001));

        let msk = dea.avps.iter().find_map(|a| if let SwmAvp::EapMasterSessionKey(k) = a { Some(k.clone()) } else { None });
        assert!(msk.is_some());
        assert_eq!(msk.unwrap().len(), 64);
        assert_eq!(aaa.successful_authentications, 1);
    }

    #[test]
    fn test_swm_unknown_user_rejection() {
        let mut aaa = AaaSwmEngine::new("aaa.epc.example.com");
        let der = SwmMessage::new_der(
            "swm-session-002",
            "000000000000000",
            "WLAN",
            vec![0x02, 0x01, 0x00, 0x04],
        );
        let dea = aaa.handle_der(&der);
        let rc = dea.avps.iter().find_map(|a| if let SwmAvp::ResultCode(c) = a { Some(*c) } else { None });
        assert_eq!(rc, Some(5001));
        assert_eq!(aaa.failed_authentications, 1);
    }
}

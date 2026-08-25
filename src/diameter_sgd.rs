//! 3GPP TS 29.338 — Diameter SGd / T4 SMS Core Delivery Interface.
//!
//! The Diameter SGd interface connects the MME (Mobility Management Entity)
//! to the SMS-SC (Short Message Service Center) / SMS-GMSC / SMS-IWMSC
//! to support native SMS over LTE (SGd / S102) and T4 cellular IoT triggers.
//!
//! This module implements:
//! * Diameter Application ID `16777313` (3GPP SGd).
//! * MO-Forward-Short-Message (OFR/OFA) — Command Code 8388645 (Mobile-Originated SMS).
//! * MT-Forward-Short-Message (TFR/TFA) — Command Code 8388646 (Mobile-Terminated SMS).
//! * Key AVPs:
//!   - `User-Name` (AVP 1, IMSI).
//!   - `SC-Address` (AVP 3300, SMS-C E.164 address).
//!   - `SM-RP-UI` (AVP 3301, SMS TPDU payload).
//!   - `SM-Delivery-Outcome` (AVP 3302).
//!   - `Result-Code` (AVP 268).
//! * `SmsSgdEngine`: SMS Relay between MME and SMS-SC, message store & delivery status tracking.

use std::collections::HashMap;

pub const DIAMETER_APPLICATION_SGD: u32 = 16777313;
pub const DIAMETER_CMD_MO_FORWARD_SM: u32 = 8388645;
pub const DIAMETER_CMD_MT_FORWARD_SM: u32 = 8388646;

pub const AVP_USER_NAME: u32 = 1;
pub const AVP_RESULT_CODE: u32 = 268;
pub const AVP_SC_ADDRESS: u32 = 3300;
pub const AVP_SM_RP_UI: u32 = 3301;
pub const AVP_SM_DELIVERY_OUTCOME: u32 = 3302;

/// Short Message Delivery Outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmDeliveryOutcome {
    Success = 0,
    AbsentSubscriber = 1,
    UserBusy = 2,
    MemoryCapacityExceeded = 3,
}

/// Diameter SGd AVP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SgdAvp {
    UserName(String),
    ScAddress(String),
    SmRpUi(Vec<u8>),
    SmDeliveryOutcome(SmDeliveryOutcome),
    ResultCode(u32),
}

/// Diameter SGd Message container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SgdMessage {
    pub command_code: u32,
    pub is_request: bool,
    pub application_id: u32,
    pub session_id: String,
    pub avps: Vec<SgdAvp>,
}

impl SgdMessage {
    /// Constructs a Mobile-Originated Short Message Request (OFR).
    pub fn new_ofr(session_id: &str, imsi: &str, sc_address: &str, tpdu: Vec<u8>) -> Self {
        SgdMessage {
            command_code: DIAMETER_CMD_MO_FORWARD_SM,
            is_request: true,
            application_id: DIAMETER_APPLICATION_SGD,
            session_id: session_id.to_string(),
            avps: vec![
                SgdAvp::UserName(imsi.to_string()),
                SgdAvp::ScAddress(sc_address.to_string()),
                SgdAvp::SmRpUi(tpdu),
            ],
        }
    }

    /// Constructs a Mobile-Terminated Short Message Request (TFR).
    pub fn new_tfr(session_id: &str, imsi: &str, sc_address: &str, tpdu: Vec<u8>) -> Self {
        SgdMessage {
            command_code: DIAMETER_CMD_MT_FORWARD_SM,
            is_request: true,
            application_id: DIAMETER_APPLICATION_SGD,
            session_id: session_id.to_string(),
            avps: vec![
                SgdAvp::UserName(imsi.to_string()),
                SgdAvp::ScAddress(sc_address.to_string()),
                SgdAvp::SmRpUi(tpdu),
            ],
        }
    }

    /// Constructs a generic Answer (OFA / TFA).
    pub fn new_answer(req: &SgdMessage, outcome: SmDeliveryOutcome, result_code: u32) -> Self {
        SgdMessage {
            command_code: req.command_code,
            is_request: false,
            application_id: req.application_id,
            session_id: req.session_id.clone(),
            avps: vec![
                SgdAvp::ResultCode(result_code),
                SgdAvp::SmDeliveryOutcome(outcome),
            ],
        }
    }
}

/// Stored Short Message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveredSms {
    pub message_id: u64,
    pub imsi: String,
    pub sc_address: String,
    pub tpdu: Vec<u8>,
    pub outcome: SmDeliveryOutcome,
}

/// 3GPP SMS-SC / MME SGd Engine.
#[derive(Debug, Clone)]
pub struct SmsSgdEngine {
    pub smsc_address: String,
    pub messages: HashMap<u64, DeliveredSms>,
    pub next_msg_id: u64,
    pub total_mo_sms: u64,
    pub total_mt_sms: u64,
}

impl SmsSgdEngine {
    pub fn new(smsc_address: &str) -> Self {
        SmsSgdEngine {
            smsc_address: smsc_address.to_string(),
            messages: HashMap::new(),
            next_msg_id: 1,
            total_mo_sms: 0,
            total_mt_sms: 0,
        }
    }

    /// Handles Mobile-Originated Short Message (OFR -> OFA).
    pub fn handle_mo_forward_sm(&mut self, ofr: &SgdMessage) -> SgdMessage {
        self.total_mo_sms += 1;
        let imsi = ofr
            .avps
            .iter()
            .find_map(|a| {
                if let SgdAvp::UserName(u) = a {
                    Some(u.clone())
                } else {
                    None
                }
            })
            .unwrap_or_default();

        let sc_addr = ofr
            .avps
            .iter()
            .find_map(|a| {
                if let SgdAvp::ScAddress(s) = a {
                    Some(s.clone())
                } else {
                    None
                }
            })
            .unwrap_or_default();

        let tpdu = ofr
            .avps
            .iter()
            .find_map(|a| {
                if let SgdAvp::SmRpUi(t) = a {
                    Some(t.clone())
                } else {
                    None
                }
            })
            .unwrap_or_default();

        let msg_id = self.next_msg_id;
        self.next_msg_id += 1;

        self.messages.insert(
            msg_id,
            DeliveredSms {
                message_id: msg_id,
                imsi,
                sc_address: sc_addr,
                tpdu,
                outcome: SmDeliveryOutcome::Success,
            },
        );

        SgdMessage::new_answer(ofr, SmDeliveryOutcome::Success, 2001) // DIAMETER_SUCCESS
    }

    /// Handles Mobile-Terminated Short Message (TFR -> TFA).
    pub fn handle_mt_forward_sm(
        &mut self,
        tfr: &SgdMessage,
        is_user_reachable: bool,
    ) -> SgdMessage {
        self.total_mt_sms += 1;
        let outcome = if is_user_reachable {
            SmDeliveryOutcome::Success
        } else {
            SmDeliveryOutcome::AbsentSubscriber
        };

        let result_code = if is_user_reachable { 2001 } else { 5005 };
        SgdMessage::new_answer(tfr, outcome, result_code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sgd_mo_sms_delivery() {
        let mut engine = SmsSgdEngine::new("+886912345678");
        let tpdu = b"Hello from 5G UE!".to_vec();

        let ofr = SgdMessage::new_ofr(
            "sess-sgd-01",
            "460011234567890",
            "+886912345678",
            tpdu.clone(),
        );
        assert_eq!(ofr.application_id, DIAMETER_APPLICATION_SGD);
        assert_eq!(ofr.command_code, DIAMETER_CMD_MO_FORWARD_SM);

        let ofa = engine.handle_mo_forward_sm(&ofr);
        assert!(!ofa.is_request);

        let rc = ofa.avps.iter().find_map(|a| {
            if let SgdAvp::ResultCode(c) = a {
                Some(*c)
            } else {
                None
            }
        });
        assert_eq!(rc, Some(2001));
        assert_eq!(engine.total_mo_sms, 1);
        assert_eq!(engine.messages.len(), 1);
        assert_eq!(engine.messages.get(&1).unwrap().tpdu, tpdu);
    }

    #[test]
    fn test_sgd_mt_sms_absent_subscriber() {
        let mut engine = SmsSgdEngine::new("+886912345678");
        let tfr = SgdMessage::new_tfr(
            "sess-sgd-02",
            "460019999999999",
            "+886912345678",
            vec![0x00, 0x01],
        );
        let tfa = engine.handle_mt_forward_sm(&tfr, false); // UE not reachable

        let outcome = tfa.avps.iter().find_map(|a| {
            if let SgdAvp::SmDeliveryOutcome(o) = a {
                Some(*o)
            } else {
                None
            }
        });
        assert_eq!(outcome, Some(SmDeliveryOutcome::AbsentSubscriber));
    }
}

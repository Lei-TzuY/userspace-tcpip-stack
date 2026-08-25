//! 3GPP TS 29.338 — Diameter S6c SMS Routing & Delivery Status Interface.
//!
//! The Diameter S6c interface connects the SMS Gateway MSC (SMS-GMSC) / SMS Interworking MSC (SMS-IWMSC)
//! to the HSS to query subscriber routing information and report message delivery outcomes.
//!
//! This module implements:
//! * Diameter Application ID `16777312` (3GPP S6c).
//! * Send-Routing-Info-for-SM (SRR / SRA — Command Code 8388647).
//! * Report-SM-Delivery-Status (RDR / RDA — Command Code 8388648).
//! * Key AVPs:
//!   - `User-Name` (AVP 1, IMSI/MSISDN).
//!   - `Serving-Node` (AVP 2401 Grouped): MME / SGSN / SMSF FQDN and IP address.
//!   - `SM-Delivery-Outcome` (AVP 3302).
//!   - `Result-Code` (AVP 268).
//! * `S6cHssEngine`: Serving node lookup, subscriber location registry, and delivery status accounting.

use crate::ipv4::Ipv4Address;
use std::collections::HashMap;

pub const DIAMETER_APPLICATION_S6C: u32 = 16777312;
pub const DIAMETER_CMD_SEND_ROUTING_INFO_FOR_SM: u32 = 8388647;
pub const DIAMETER_CMD_REPORT_SM_DELIVERY_STATUS: u32 = 8388648;

/// Type of Serving Node for SMS delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S6cServingNodeType {
    Mme,
    Sgsn,
    Smsf,
}

/// Serving Node details returned in SRA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S6cServingNodeInfo {
    pub node_type: S6cServingNodeType,
    pub node_fqdn: String,
    pub node_ip: Ipv4Address,
}

/// Diameter S6c AVP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S6cAvp {
    UserName(String),
    ServingNode(S6cServingNodeInfo),
    SmDeliveryOutcome(u32), // 0: Successful, 1: Absent, 2: MemoryFull
    ResultCode(u32),
}

/// Diameter S6c Message Container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S6cMessage {
    pub command_code: u32,
    pub is_request: bool,
    pub application_id: u32,
    pub session_id: String,
    pub avps: Vec<S6cAvp>,
}

impl S6cMessage {
    pub fn new_srr(session_id: &str, msisdn_or_imsi: &str) -> Self {
        S6cMessage {
            command_code: DIAMETER_CMD_SEND_ROUTING_INFO_FOR_SM,
            is_request: true,
            application_id: DIAMETER_APPLICATION_S6C,
            session_id: session_id.to_string(),
            avps: vec![S6cAvp::UserName(msisdn_or_imsi.to_string())],
        }
    }

    pub fn new_rdr(session_id: &str, msisdn_or_imsi: &str, outcome: u32) -> Self {
        S6cMessage {
            command_code: DIAMETER_CMD_REPORT_SM_DELIVERY_STATUS,
            is_request: true,
            application_id: DIAMETER_APPLICATION_S6C,
            session_id: session_id.to_string(),
            avps: vec![
                S6cAvp::UserName(msisdn_or_imsi.to_string()),
                S6cAvp::SmDeliveryOutcome(outcome),
            ],
        }
    }

    pub fn new_answer(req: &S6cMessage, result_code: u32) -> Self {
        S6cMessage {
            command_code: req.command_code,
            is_request: false,
            application_id: req.application_id,
            session_id: req.session_id.clone(),
            avps: vec![S6cAvp::ResultCode(result_code)],
        }
    }

    pub fn add_avp(&mut self, avp: S6cAvp) {
        self.avps.push(avp);
    }
}

/// HSS S6c Routing & Status Engine.
#[derive(Debug, Clone)]
pub struct S6cHssEngine {
    pub hss_realm: String,
    /// User (IMSI/MSISDN) -> S6cServingNodeInfo
    pub routing_registry: HashMap<String, S6cServingNodeInfo>,
    pub total_srr_requests: u64,
    pub total_rdr_reports: u64,
}

impl S6cHssEngine {
    pub fn new(hss_realm: &str) -> Self {
        S6cHssEngine {
            hss_realm: hss_realm.to_string(),
            routing_registry: HashMap::new(),
            total_srr_requests: 0,
            total_rdr_reports: 0,
        }
    }

    pub fn register_subscriber_location(&mut self, user_id: &str, info: S6cServingNodeInfo) {
        self.routing_registry.insert(user_id.to_string(), info);
    }

    /// Handles Send-Routing-Info-for-SM (SRR) and answers with Serving-Node in SRA.
    pub fn handle_srr(&mut self, srr: &S6cMessage) -> S6cMessage {
        self.total_srr_requests += 1;
        let user = srr
            .avps
            .iter()
            .find_map(|a| {
                if let S6cAvp::UserName(u) = a {
                    Some(u.clone())
                } else {
                    None
                }
            })
            .unwrap_or_default();

        if let Some(info) = self.routing_registry.get(&user) {
            let mut sra = S6cMessage::new_answer(srr, 2001); // DIAMETER_SUCCESS
            sra.add_avp(S6cAvp::ServingNode(info.clone()));
            sra
        } else {
            S6cMessage::new_answer(srr, 5001) // DIAMETER_ERROR_USER_UNKNOWN
        }
    }

    /// Handles Report-SM-Delivery-Status (RDR).
    pub fn handle_rdr(&mut self, rdr: &S6cMessage) -> S6cMessage {
        self.total_rdr_reports += 1;
        S6cMessage::new_answer(rdr, 2001)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diameter_s6c_srr_and_rdr() {
        let mut hss = S6cHssEngine::new("hss.epc.mnc001.mcc460.3gppnetwork.org");
        let serving_mme = S6cServingNodeInfo {
            node_type: S6cServingNodeType::Mme,
            node_fqdn: "mme01.epc.operator.com".to_string(),
            node_ip: Ipv4Address::new(10, 20, 30, 40),
        };
        hss.register_subscriber_location("886912345678", serving_mme.clone());

        // 1. SRR Request
        let srr = S6cMessage::new_srr("s6c-sess-01", "886912345678");
        assert_eq!(srr.application_id, DIAMETER_APPLICATION_S6C);
        assert_eq!(srr.command_code, DIAMETER_CMD_SEND_ROUTING_INFO_FOR_SM);

        let sra = hss.handle_srr(&srr);
        assert!(!sra.is_request);
        let rc = sra.avps.iter().find_map(|a| {
            if let S6cAvp::ResultCode(c) = a {
                Some(*c)
            } else {
                None
            }
        });
        assert_eq!(rc, Some(2001));

        let node = sra.avps.iter().find_map(|a| {
            if let S6cAvp::ServingNode(n) = a {
                Some(n.clone())
            } else {
                None
            }
        });
        assert_eq!(node, Some(serving_mme));
        assert_eq!(hss.total_srr_requests, 1);

        // 2. RDR Report
        let rdr = S6cMessage::new_rdr("s6c-sess-02", "886912345678", 0);
        let rda = hss.handle_rdr(&rdr);
        let rc_rdr = rda.avps.iter().find_map(|a| {
            if let S6cAvp::ResultCode(c) = a {
                Some(*c)
            } else {
                None
            }
        });
        assert_eq!(rc_rdr, Some(2001));
        assert_eq!(hss.total_rdr_reports, 1);
    }
}

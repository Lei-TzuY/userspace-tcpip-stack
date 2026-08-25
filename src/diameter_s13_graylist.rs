//! 3GPP TS 29.272 — Diameter S13 Equipment Identity Check with Graylist Throttling.
//!
//! The Equipment Identity Register (EIR) verifies IMEI / IMEI-SV to detect stolen,
//! unauthorized, or malfunctioning mobile devices:
//!
//! * **White-Listed (0)**: Normal device with full network service access.
//! * **Black-Listed (1)**: Stolen/fraudulent device; network access is completely barred.
//! * **Grey-Listed (2)**: Under observation (e.g. non-type-approved or suspected clone);
//!   allowed access but subject to dynamic rate throttling and monitoring.
//!
//! This module implements:
//! * Diameter S13 ME-Identity-Check-Request / Answer (ECR / ECA — Command Code 324).
//! * Equipment Status mapping with QoS rate limit enforcement.
//! * `EirGraylistEngine`: Evaluates IMEI status and returns policy actions.

use std::collections::HashMap;

pub const DIAMETER_APPLICATION_S13: u32 = 16777252;
pub const DIAMETER_CMD_ME_IDENTITY_CHECK: u32 = 324;

/// 3GPP Equipment Status per TS 29.272.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EirStatus {
    WhiteListed = 0,
    BlackListed = 1,
    GreyListed = 2,
}

/// Dynamic QoS Policy Action for Equipment Status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EirQosAction {
    FullAccess,
    DropAccess,
    ThrottledAccess { max_kbps: u32 },
}

/// S13 Diameter AVP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S13GraylistAvp {
    TerminalInformation(String),
    EquipmentStatus(EirStatus),
    ResultCode(u32),
}

/// S13 Diameter Message Container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S13GraylistMessage {
    pub command_code: u32,
    pub is_request: bool,
    pub application_id: u32,
    pub session_id: String,
    pub avps: Vec<S13GraylistAvp>,
}

impl S13GraylistMessage {
    pub fn new_ecr(session_id: &str, imei: &str) -> Self {
        S13GraylistMessage {
            command_code: DIAMETER_CMD_ME_IDENTITY_CHECK,
            is_request: true,
            application_id: DIAMETER_APPLICATION_S13,
            session_id: session_id.to_string(),
            avps: vec![S13GraylistAvp::TerminalInformation(imei.to_string())],
        }
    }

    pub fn new_eca(req: &S13GraylistMessage, result_code: u32, status: EirStatus) -> Self {
        S13GraylistMessage {
            command_code: req.command_code,
            is_request: false,
            application_id: req.application_id,
            session_id: req.session_id.clone(),
            avps: vec![
                S13GraylistAvp::ResultCode(result_code),
                S13GraylistAvp::EquipmentStatus(status),
            ],
        }
    }
}

/// EIR Engine with Graylist Rate Throttling Logic.
#[derive(Debug, Clone)]
pub struct EirGraylistEngine {
    pub eir_realm: String,
    /// IMEI -> EirStatus
    pub imei_database: HashMap<String, EirStatus>,
    pub graylist_rate_limit_kbps: u32,
    pub total_ecr_checks: u64,
}

impl EirGraylistEngine {
    pub fn new(eir_realm: &str, graylist_rate_limit_kbps: u32) -> Self {
        EirGraylistEngine {
            eir_realm: eir_realm.to_string(),
            imei_database: HashMap::new(),
            graylist_rate_limit_kbps,
            total_ecr_checks: 0,
        }
    }

    pub fn set_imei_status(&mut self, imei: &str, status: EirStatus) {
        self.imei_database.insert(imei.to_string(), status);
    }

    /// Handles ECR request and determines equipment status and QoS policy action.
    pub fn handle_ecr(&mut self, ecr: &S13GraylistMessage) -> (S13GraylistMessage, EirQosAction) {
        self.total_ecr_checks += 1;

        let imei = ecr
            .avps
            .iter()
            .find_map(|a| {
                if let S13GraylistAvp::TerminalInformation(i) = a {
                    Some(i.clone())
                } else {
                    None
                }
            })
            .unwrap_or_default();

        let status = self
            .imei_database
            .get(&imei)
            .copied()
            .unwrap_or(EirStatus::WhiteListed);

        let qos_action = match status {
            EirStatus::WhiteListed => EirQosAction::FullAccess,
            EirStatus::BlackListed => EirQosAction::DropAccess,
            EirStatus::GreyListed => EirQosAction::ThrottledAccess {
                max_kbps: self.graylist_rate_limit_kbps,
            },
        };

        let eca = S13GraylistMessage::new_eca(ecr, 2001, status);
        (eca, qos_action)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eir_graylist_throttling_decision() {
        let mut eir = EirGraylistEngine::new("eir.telco.net", 256);

        eir.set_imei_status("861234567890123", EirStatus::GreyListed);
        eir.set_imei_status("869999999999999", EirStatus::BlackListed);

        // 1. Check Graylisted device
        let ecr1 = S13GraylistMessage::new_ecr("s13-sess-1", "861234567890123");
        let (eca1, qos1) = eir.handle_ecr(&ecr1);
        let st1 = eca1.avps.iter().find_map(|a| {
            if let S13GraylistAvp::EquipmentStatus(s) = a {
                Some(*s)
            } else {
                None
            }
        });
        assert_eq!(st1, Some(EirStatus::GreyListed));
        assert_eq!(qos1, EirQosAction::ThrottledAccess { max_kbps: 256 });

        // 2. Check Blacklisted device
        let ecr2 = S13GraylistMessage::new_ecr("s13-sess-2", "869999999999999");
        let (_eca2, qos2) = eir.handle_ecr(&ecr2);
        assert_eq!(qos2, EirQosAction::DropAccess);

        // 3. Check unknown (default WhiteListed)
        let ecr3 = S13GraylistMessage::new_ecr("s13-sess-3", "860000000000000");
        let (_eca3, qos3) = eir.handle_ecr(&ecr3);
        assert_eq!(qos3, EirQosAction::FullAccess);
        assert_eq!(eir.total_ecr_checks, 3);
    }
}

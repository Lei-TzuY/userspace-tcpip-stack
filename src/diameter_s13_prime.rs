//! 3GPP TS 29.272 Section 6 — Diameter S13' Equipment Identity Register (EIR) Interface.
//!
//! The Diameter S13' interface connects the MME / SGSN / AMF directly to the
//! EIR to verify the status of the Mobile Equipment (ME) identity (IMEI / IMEI-SV).
//!
//! This module implements:
//! * Diameter Application ID `16777252` (3GPP S13').
//! * ME-Identity-Check-Request (ECR) / Answer (ECA) — Command Code 324.
//! * Key S13' AVPs:
//!   - `Terminal-Information` (AVP 1401, Grouped):
//!     * `IMEI` (AVP 1402, 15-digit TAC+SNR+CD)
//!     * `Software-Version` (AVP 1403, 2-digit SVN)
//!   - `Equipment-Status` (AVP 1445): Whitelisted (0), Blacklisted (1), Greylisted (2).
//!   - `User-Name` (AVP 1, IMSI).
//!   - `Result-Code` (AVP 268).
//! * `EirS13PrimeEngine`: Multi-device tracking, rogue firmware SVN detection, and EIR status query.

use std::collections::HashMap;

pub const DIAMETER_APPLICATION_S13_PRIME: u32 = 16777252;
pub const DIAMETER_CMD_ME_IDENTITY_CHECK: u32 = 324;

pub const AVP_USER_NAME: u32 = 1;
pub const AVP_RESULT_CODE: u32 = 268;
pub const AVP_TERMINAL_INFORMATION: u32 = 1401;
pub const AVP_IMEI: u32 = 1402;
pub const AVP_SOFTWARE_VERSION: u32 = 1403;
pub const AVP_EQUIPMENT_STATUS: u32 = 1445;

/// Mobile Equipment Status per 3GPP TS 29.272.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EquipmentStatus {
    Whitelisted = 0,
    Blacklisted = 1,
    Greylisted = 2,
}

impl EquipmentStatus {
    pub fn as_u32(self) -> u32 {
        self as u32
    }

    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            0 => Some(Self::Whitelisted),
            1 => Some(Self::Blacklisted),
            2 => Some(Self::Greylisted),
            _ => None,
        }
    }
}

/// Terminal-Information Grouped AVP 1401.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalInformation {
    pub imei: String,
    pub software_version: Option<String>,
}

impl TerminalInformation {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // AVP 1402: IMEI
        buf.extend_from_slice(&AVP_IMEI.to_be_bytes());
        let imei_b = self.imei.as_bytes();
        buf.extend_from_slice(&(imei_b.len() as u16).to_be_bytes());
        buf.extend_from_slice(imei_b);

        // AVP 1403: Software-Version (optional)
        if let Some(ref sv) = self.software_version {
            buf.extend_from_slice(&AVP_SOFTWARE_VERSION.to_be_bytes());
            let sv_b = sv.as_bytes();
            buf.extend_from_slice(&(sv_b.len() as u16).to_be_bytes());
            buf.extend_from_slice(sv_b);
        }
        buf
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        let mut offset = 0;
        let mut imei = String::new();
        let mut software_version = None;

        while offset + 6 <= data.len() {
            let code = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            let len = u16::from_be_bytes([data[offset + 4], data[offset + 5]]) as usize;
            offset += 6;
            if offset + len > data.len() {
                break;
            }
            let val = &data[offset..offset + len];
            if code == AVP_IMEI {
                imei = String::from_utf8_lossy(val).to_string();
            } else if code == AVP_SOFTWARE_VERSION {
                software_version = Some(String::from_utf8_lossy(val).to_string());
            }
            offset += len;
        }

        if imei.is_empty() {
            None
        } else {
            Some(TerminalInformation {
                imei,
                software_version,
            })
        }
    }
}

/// S13' Diameter AVP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S13PrimeAvp {
    UserName(String),
    TerminalInformation(TerminalInformation),
    EquipmentStatus(EquipmentStatus),
    ResultCode(u32),
}

/// Diameter S13' Message container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S13PrimeMessage {
    pub command_code: u32,
    pub is_request: bool,
    pub application_id: u32,
    pub session_id: String,
    pub avps: Vec<S13PrimeAvp>,
}

impl S13PrimeMessage {
    pub fn new_ecr(session_id: &str, user_name: &str, terminal_info: TerminalInformation) -> Self {
        S13PrimeMessage {
            command_code: DIAMETER_CMD_ME_IDENTITY_CHECK,
            is_request: true,
            application_id: DIAMETER_APPLICATION_S13_PRIME,
            session_id: session_id.to_string(),
            avps: vec![
                S13PrimeAvp::UserName(user_name.to_string()),
                S13PrimeAvp::TerminalInformation(terminal_info),
            ],
        }
    }

    pub fn new_eca(req: &S13PrimeMessage, status: EquipmentStatus, result_code: u32) -> Self {
        S13PrimeMessage {
            command_code: req.command_code,
            is_request: false,
            application_id: req.application_id,
            session_id: req.session_id.clone(),
            avps: vec![
                S13PrimeAvp::ResultCode(result_code),
                S13PrimeAvp::EquipmentStatus(status),
            ],
        }
    }
}

/// Enhanced 3GPP EIR Server Engine implementing the Diameter S13' interface.
#[derive(Debug, Clone)]
pub struct EirS13PrimeEngine {
    pub eir_realm: String,
    pub equipment_db: HashMap<String, EquipmentStatus>,
    pub banned_software_versions: Vec<String>,
    pub total_checks: u64,
    pub blacklisted_hits: u64,
}

impl EirS13PrimeEngine {
    pub fn new(eir_realm: &str) -> Self {
        EirS13PrimeEngine {
            eir_realm: eir_realm.to_string(),
            equipment_db: HashMap::new(),
            banned_software_versions: Vec::new(),
            total_checks: 0,
            blacklisted_hits: 0,
        }
    }

    /// Sets equipment status for an IMEI.
    pub fn register_equipment(&mut self, imei: &str, status: EquipmentStatus) {
        self.equipment_db.insert(imei.to_string(), status);
    }

    /// Adds a known vulnerable/rogue firmware Software Version (SVN).
    pub fn ban_software_version(&mut self, svn: &str) {
        self.banned_software_versions.push(svn.to_string());
    }

    /// Processes an ME-Identity-Check Request (ECR) and returns Answer (ECA).
    pub fn process_ecr(&mut self, ecr: &S13PrimeMessage) -> S13PrimeMessage {
        self.total_checks += 1;
        let term_info = ecr.avps.iter().find_map(|a| {
            if let S13PrimeAvp::TerminalInformation(t) = a {
                Some(t.clone())
            } else {
                None
            }
        });

        if let Some(info) = term_info {
            // Check if software version is banned -> force Graylist
            if let Some(ref sv) = info.software_version {
                if self.banned_software_versions.contains(sv) {
                    return S13PrimeMessage::new_eca(ecr, EquipmentStatus::Greylisted, 2001);
                }
            }

            let status = self
                .equipment_db
                .get(&info.imei)
                .copied()
                .unwrap_or(EquipmentStatus::Whitelisted);
            if status == EquipmentStatus::Blacklisted {
                self.blacklisted_hits += 1;
            }
            S13PrimeMessage::new_eca(ecr, status, 2001)
        } else {
            S13PrimeMessage::new_eca(ecr, EquipmentStatus::Whitelisted, 5004)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_s13_prime_ecr_eca_whitelisted() {
        let mut eir = EirS13PrimeEngine::new("eir.mnc001.mcc001.3gppnetwork.org");
        eir.register_equipment("861234567890123", EquipmentStatus::Whitelisted);

        let term_info = TerminalInformation {
            imei: "861234567890123".into(),
            software_version: Some("01".into()),
        };

        let ecr = S13PrimeMessage::new_ecr("sess-s13p-1", "001010000000001", term_info);
        let eca = eir.process_ecr(&ecr);

        assert_eq!(eca.application_id, DIAMETER_APPLICATION_S13_PRIME);
        assert_eq!(eca.command_code, DIAMETER_CMD_ME_IDENTITY_CHECK);
        assert!(!eca.is_request);

        let status = eca.avps.iter().find_map(|a| {
            if let S13PrimeAvp::EquipmentStatus(s) = a {
                Some(*s)
            } else {
                None
            }
        });
        assert_eq!(status, Some(EquipmentStatus::Whitelisted));
        assert_eq!(eir.total_checks, 1);
    }

    #[test]
    fn test_s13_prime_banned_software_version_greylisted() {
        let mut eir = EirS13PrimeEngine::new("eir.operator.com");
        eir.register_equipment("869999999999999", EquipmentStatus::Whitelisted);
        eir.ban_software_version("99"); // Vulnerable rogue SVN

        let term_info = TerminalInformation {
            imei: "869999999999999".into(),
            software_version: Some("99".into()),
        };

        let ecr = S13PrimeMessage::new_ecr("sess-s13p-2", "001010000000002", term_info);
        let eca = eir.process_ecr(&ecr);

        let status = eca.avps.iter().find_map(|a| {
            if let S13PrimeAvp::EquipmentStatus(s) = a {
                Some(*s)
            } else {
                None
            }
        });
        assert_eq!(status, Some(EquipmentStatus::Greylisted));
    }
}

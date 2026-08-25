//! 3GPP Diameter S13 / S13' EIR Equipment Identity Register Interface (3GPP TS 29.272 Section 6).
//!
//! Implements ME-Identity-Check-Request / Answer (ECR/ECA - Command Code 324, Application ID 16777252),
//! Terminal-Information (AVP 1401), Equipment-Status (AVP 1445: Whitelisted, Blacklisted, Greylisted),
//! and stolen/unapproved mobile equipment barring policies for 5G/4G core networks.

use crate::diameter::{
    DiameterAvp, DiameterMessage, DIAMETER_FLAG_MANDATORY, DIAMETER_FLAG_VENDOR_SPECIFIC,
    DIAMETER_SUCCESS,
};
use crate::diameter_gx::VENDOR_3GPP;
use std::collections::HashMap;

/// Diameter Application ID for 3GPP S13 / S13' Interface (3GPP TS 29.272).
pub const DIAMETER_APPLICATION_S13: u32 = 16777252;

/// ME-Identity-Check-Request / Answer Command Code (ECR/ECA).
pub const DIAMETER_CMD_ME_IDENTITY_CHECK: u32 = 324;

/// 3GPP S13 AVP Codes.
pub const AVP_TERMINAL_INFORMATION: u32 = 1401;
pub const AVP_IMEI: u32 = 1402;
pub const AVP_SOFTWARE_VERSION: u32 = 1403;
pub const AVP_EQUIPMENT_STATUS: u32 = 1445;

/// Mobile Equipment Status in EIR (3GPP TS 29.272 Section 7.3.51).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EquipmentStatus {
    /// Permitted to connect to network.
    Whitelisted = 0,
    /// Barred / Stolen device (Access denied).
    Blacklisted = 1,
    /// Under tracking / observation.
    Greylisted = 2,
}

impl EquipmentStatus {
    pub fn from_u32(val: u32) -> Self {
        match val {
            1 => EquipmentStatus::Blacklisted,
            2 => EquipmentStatus::Greylisted,
            _ => EquipmentStatus::Whitelisted,
        }
    }
}

/// Equipment Identity Register (EIR) S13 Protocol Engine.
#[derive(Debug, Clone, Default)]
pub struct EirS13Engine {
    pub imei_status_db: HashMap<String, EquipmentStatus>,
    pub total_checks_count: usize,
    pub blacklisted_drops_count: usize,
}

impl EirS13Engine {
    pub fn new() -> Self {
        EirS13Engine {
            imei_status_db: HashMap::new(),
            total_checks_count: 0,
            blacklisted_drops_count: 0,
        }
    }

    /// Registers or updates the status of an IMEI in the EIR database.
    pub fn set_imei_status(&mut self, imei: &str, status: EquipmentStatus) {
        self.imei_status_db.insert(imei.to_string(), status);
    }

    /// Queries the equipment status for an IMEI.
    pub fn query_imei(&mut self, imei: &str) -> EquipmentStatus {
        self.total_checks_count += 1;
        let status = self.imei_status_db.get(imei).copied().unwrap_or(EquipmentStatus::Whitelisted);
        if status == EquipmentStatus::Blacklisted {
            self.blacklisted_drops_count += 1;
        }
        status
    }

    /// Handles an incoming ME-Identity-Check-Request (ECR) and returns ME-Identity-Check-Answer (ECA).
    pub fn handle_ecr(&mut self, imei: &str) -> DiameterMessage {
        let status = self.query_imei(imei);

        let mut eca = DiameterMessage::new_answer(
            DIAMETER_CMD_ME_IDENTITY_CHECK,
            DIAMETER_APPLICATION_S13,
            1,
            1,
        );

        eca.add_avp(DiameterAvp::new_u32(268, DIAMETER_SUCCESS));

        // Equipment-Status AVP (AVP 1445, Vendor 10415)
        let status_val = (status as u32).to_be_bytes();
        let status_avp = DiameterAvp::new_vendor(
            AVP_EQUIPMENT_STATUS,
            DIAMETER_FLAG_MANDATORY | DIAMETER_FLAG_VENDOR_SPECIFIC,
            VENDOR_3GPP,
            &status_val,
        );
        eca.add_avp(status_avp);

        eca
    }
}

//! 3GPP TS 29.217 — Diameter Np RAN User Plane Congestion Awareness Interface.
//!
//! The Diameter Np interface connects the RAN Congestion Awareness Function (RCAF)
//! to the PCRF to report cell-level radio access network (RAN) user-plane congestion status.
//! This allows policy controllers to dynamically throttle background/best-effort APNs during peak hours.
//!
//! This module implements:
//! * Diameter Application ID `16777342` (3GPP Np).
//! * Non-Aggregated-RUCI-Report (NCR / NCA — Command Code 8388725).
//! * Key AVPs:
//!   - `User-Name` (AVP 1, IMSI).
//!   - `RAN-Congestion-Info` (AVP 4001 Grouped): Cell-ID, Congestion-Level.
//!   - `Congestion-Level` (AVP 4002): None (0), Low (1), Medium (2), High (3).
//!   - `eNodeB-ID` (AVP 4003).
//!   - `Result-Code` (AVP 268).
//! * `RcafNpEngine`: Ingests cell congestion telemetry and tracks active PCRF notifications.

use std::collections::HashMap;

pub const DIAMETER_APPLICATION_NP: u32 = 16777342;
pub const DIAMETER_CMD_NON_AGGREGATED_RUCI_REPORT: u32 = 8388725;

/// RAN Congestion Level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RanCongestionLevel {
    None = 0,
    Low = 1,
    Medium = 2,
    High = 3,
}

/// RAN Congestion Information Grouped AVP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RanCongestionInfo {
    pub enodeb_id: u32,
    pub cell_id: u32,
    pub level: RanCongestionLevel,
}

/// Diameter Np AVP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NpAvp {
    UserName(String),
    RanCongestion(RanCongestionInfo),
    ResultCode(u32),
}

/// Diameter Np Message Container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpMessage {
    pub command_code: u32,
    pub is_request: bool,
    pub application_id: u32,
    pub session_id: String,
    pub avps: Vec<NpAvp>,
}

impl NpMessage {
    pub fn new_ncr(session_id: &str, imsi: &str, info: RanCongestionInfo) -> Self {
        NpMessage {
            command_code: DIAMETER_CMD_NON_AGGREGATED_RUCI_REPORT,
            is_request: true,
            application_id: DIAMETER_APPLICATION_NP,
            session_id: session_id.to_string(),
            avps: vec![
                NpAvp::UserName(imsi.to_string()),
                NpAvp::RanCongestion(info),
            ],
        }
    }

    pub fn new_nca(req: &NpMessage, result_code: u32) -> Self {
        NpMessage {
            command_code: req.command_code,
            is_request: false,
            application_id: req.application_id,
            session_id: req.session_id.clone(),
            avps: vec![NpAvp::ResultCode(result_code)],
        }
    }
}

/// PCRF / RCAF Diameter Np Engine.
#[derive(Debug, Clone)]
pub struct RcafNpEngine {
    pub pcrf_realm: String,
    /// (eNodeB, Cell) -> RanCongestionLevel
    pub cell_congestion_map: HashMap<(u32, u32), RanCongestionLevel>,
    pub total_ncr_reports: u64,
}

impl RcafNpEngine {
    pub fn new(pcrf_realm: &str) -> Self {
        RcafNpEngine {
            pcrf_realm: pcrf_realm.to_string(),
            cell_congestion_map: HashMap::new(),
            total_ncr_reports: 0,
        }
    }

    /// Handles Non-Aggregated-RUCI-Report (NCR) from RCAF and updates PCRF state.
    pub fn handle_ncr(&mut self, ncr: &NpMessage) -> NpMessage {
        self.total_ncr_reports += 1;

        for avp in &ncr.avps {
            if let NpAvp::RanCongestion(info) = avp {
                self.cell_congestion_map.insert((info.enodeb_id, info.cell_id), info.level);
            }
        }

        NpMessage::new_nca(ncr, 2001) // DIAMETER_SUCCESS
    }

    pub fn get_cell_congestion(&self, enodeb_id: u32, cell_id: u32) -> RanCongestionLevel {
        self.cell_congestion_map.get(&(enodeb_id, cell_id)).copied().unwrap_or(RanCongestionLevel::None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diameter_np_ruci_congestion_reporting() {
        let mut pcrf = RcafNpEngine::new("pcrf.operator.com");

        let congestion = RanCongestionInfo {
            enodeb_id: 1001,
            cell_id: 1,
            level: RanCongestionLevel::High,
        };
        let ncr = NpMessage::new_ncr("np-sess-100", "460012345678901", congestion);
        assert_eq!(ncr.application_id, DIAMETER_APPLICATION_NP);
        assert_eq!(ncr.command_code, DIAMETER_CMD_NON_AGGREGATED_RUCI_REPORT);

        let nca = pcrf.handle_ncr(&ncr);
        assert!(!nca.is_request);
        let rc = nca.avps.iter().find_map(|a| if let NpAvp::ResultCode(c) = a { Some(*c) } else { None });
        assert_eq!(rc, Some(2001));

        assert_eq!(pcrf.get_cell_congestion(1001, 1), RanCongestionLevel::High);
        assert_eq!(pcrf.get_cell_congestion(1001, 2), RanCongestionLevel::None);
        assert_eq!(pcrf.total_ncr_reports, 1);
    }
}

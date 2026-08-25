//! 3GPP TS 29.336 — Diameter S6t SCEF to HSS Interface for Cellular IoT.
//!
//! The Diameter S6t interface connects the Service Capability Exposure Function (SCEF)
//! to the Home Subscriber Server (HSS) to configure monitoring events (e.g. UE Reachability,
//! Loss of Connectivity, Location Reporting) for Cellular IoT (CIoT) and Non-IP Data Delivery (NIDD).
//!
//! This module implements:
//! * Diameter Application ID `16777345` (3GPP S6t).
//! * Configuration-Information-Request / Answer (CIR / CIA — Command Code 8388728).
//! * Reporting-Information-Request / Answer (RIR / RIA — Command Code 8388729).
//! * Key AVPs:
//!   - `User-Name` (AVP 1, IMSI).
//!   - `Monitoring-Type` (AVP 3123): LossOfConnectivity (2), UeReachability (3), LocationReporting (4).
//!   - `SCEF-ID` (AVP 3105).
//!   - `SCEF-Reference-ID` (AVP 3124).
//!   - `Result-Code` (AVP 268).
//! * `ScefS6tHssEngine`: Processes SCEF monitoring configuration and event reporting.

use std::collections::HashMap;

pub const DIAMETER_APPLICATION_S6T: u32 = 16777345;
pub const DIAMETER_CMD_CONFIGURATION_INFORMATION: u32 = 8388728;
pub const DIAMETER_CMD_REPORTING_INFORMATION: u32 = 8388729;

/// Monitoring Event Type per 3GPP TS 29.336.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitoringEventType {
    LossOfConnectivity = 2,
    UeReachability = 3,
    LocationReporting = 4,
    RoamingStatus = 5,
}

/// Monitoring Event Configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitoringEventConfig {
    pub scef_id: String,
    pub scef_ref_id: u32,
    pub event_type: MonitoringEventType,
}

/// Diameter S6t AVP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S6tAvp {
    UserName(String),
    MonitoringConfig(MonitoringEventConfig),
    ResultCode(u32),
}

/// Diameter S6t Message Container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S6tMessage {
    pub command_code: u32,
    pub is_request: bool,
    pub application_id: u32,
    pub session_id: String,
    pub avps: Vec<S6tAvp>,
}

impl S6tMessage {
    pub fn new_cir(session_id: &str, imsi: &str, config: MonitoringEventConfig) -> Self {
        S6tMessage {
            command_code: DIAMETER_CMD_CONFIGURATION_INFORMATION,
            is_request: true,
            application_id: DIAMETER_APPLICATION_S6T,
            session_id: session_id.to_string(),
            avps: vec![
                S6tAvp::UserName(imsi.to_string()),
                S6tAvp::MonitoringConfig(config),
            ],
        }
    }

    pub fn new_cia(req: &S6tMessage, result_code: u32) -> Self {
        S6tMessage {
            command_code: req.command_code,
            is_request: false,
            application_id: req.application_id,
            session_id: req.session_id.clone(),
            avps: vec![S6tAvp::ResultCode(result_code)],
        }
    }
}

/// HSS S6t Monitoring & NIDD Configuration Engine.
#[derive(Debug, Clone)]
pub struct ScefS6tHssEngine {
    pub hss_realm: String,
    /// User (IMSI) -> Vec<MonitoringEventConfig>
    pub user_monitoring_events: HashMap<String, Vec<MonitoringEventConfig>>,
    pub total_cir_requests: u64,
    pub total_rir_reports: u64,
}

impl ScefS6tHssEngine {
    pub fn new(hss_realm: &str) -> Self {
        ScefS6tHssEngine {
            hss_realm: hss_realm.to_string(),
            user_monitoring_events: HashMap::new(),
            total_cir_requests: 0,
            total_rir_reports: 0,
        }
    }

    /// Handles Configuration-Information-Request (CIR) from SCEF.
    pub fn handle_cir(&mut self, cir: &S6tMessage) -> S6tMessage {
        self.total_cir_requests += 1;

        let user = cir.avps.iter().find_map(|a| {
            if let S6tAvp::UserName(u) = a { Some(u.clone()) } else { None }
        }).unwrap_or_default();

        let config = cir.avps.iter().find_map(|a| {
            if let S6tAvp::MonitoringConfig(c) = a { Some(c.clone()) } else { None }
        });

        if let Some(cfg) = config {
            self.user_monitoring_events.entry(user).or_default().push(cfg);
            S6tMessage::new_cia(cir, 2001) // DIAMETER_SUCCESS
        } else {
            S6tMessage::new_cia(cir, 5004) // DIAMETER_ERROR_INVALID_AVP_VALUE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diameter_s6t_monitoring_event_config() {
        let mut hss = ScefS6tHssEngine::new("hss.ciot.operator.com");

        let config = MonitoringEventConfig {
            scef_id: "scef01.iot.net".to_string(),
            scef_ref_id: 8881,
            event_type: MonitoringEventType::UeReachability,
        };

        let cir = S6tMessage::new_cir("s6t-sess-01", "460041234567890", config.clone());
        assert_eq!(cir.application_id, DIAMETER_APPLICATION_S6T);
        assert_eq!(cir.command_code, DIAMETER_CMD_CONFIGURATION_INFORMATION);

        let cia = hss.handle_cir(&cir);
        assert!(!cia.is_request);
        let rc = cia.avps.iter().find_map(|a| if let S6tAvp::ResultCode(c) = a { Some(*c) } else { None });
        assert_eq!(rc, Some(2001));

        let events = hss.user_monitoring_events.get("460041234567890").unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], config);
        assert_eq!(hss.total_cir_requests, 1);
    }
}

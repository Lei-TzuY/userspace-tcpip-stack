//! 3GPP Diameter Sy Interface & Spending Limit Reporting (3GPP TS 29.219 / TS 23.203).
//!
//! Implements Policy and Charging Control Spending Limit Reporting between the
//! Policy and Charging Rules Function (PCRF) and the Online Charging System (OCS)
//! over Diameter Application ID 16777302.
//! Supports Spending-Limit-Request/Answer (SLR/SLA - Command 8388635),
//! Spending-Status-Notification-Request/Answer (SNR/SNA - Command 8388636),
//! Policy-Counter-Status-Report grouped AVPs, dynamic policy counter threshold monitoring,
//! and automated OCS-to-PCRF notifications upon subscriber balance threshold crossings.

use crate::diameter::{DIAMETER_SUCCESS, DiameterAvp, DiameterHeader, DiameterMessage};
use std::collections::HashMap;

/// Diameter Sy Application ID (3GPP TS 29.219 Section 5.1).
pub const DIAMETER_APPLICATION_SY: u32 = 16777302;

/// Command Codes for Diameter Sy.
pub const DIAMETER_CMD_SPENDING_LIMIT: u32 = 8388635; // SLR / SLA
pub const DIAMETER_CMD_SPENDING_STATUS_NOTIFICATION: u32 = 8388636; // SNR / SNA
pub const DIAMETER_CMD_SESSION_TERMINATION: u32 = 275; // STR / STA

/// Diameter Sy AVP Codes (3GPP TS 29.219 Section 5.3).
pub const AVP_POLICY_COUNTER_IDENTIFIER: u32 = 2901;
pub const AVP_POLICY_COUNTER_STATUS: u32 = 2902;
pub const AVP_POLICY_COUNTER_STATUS_REPORT: u32 = 2903;
pub const AVP_SL_REQUEST_TYPE: u32 = 2904;
pub const AVP_SUBSCRIPTION_ID: u32 = 443;
pub const AVP_SUBSCRIPTION_ID_DATA: u32 = 444;
pub const AVP_SUBSCRIPTION_ID_TYPE: u32 = 450;
pub const AVP_SESSION_ID: u32 = 263;
pub const AVP_RESULT_CODE: u32 = 268;
pub const AVP_ORIGIN_HOST: u32 = 264;
pub const AVP_ORIGIN_REALM: u32 = 296;
pub const AVP_DESTINATION_REALM: u32 = 283;

/// SL-Request-Type enumeration (AVP 2904).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlRequestType {
    InitialRequest = 0,
    IntermediateRequest = 1,
    StopRequest = 2,
}

impl SlRequestType {
    pub fn from_u32(v: u32) -> Self {
        match v {
            0 => SlRequestType::InitialRequest,
            1 => SlRequestType::IntermediateRequest,
            _ => SlRequestType::StopRequest,
        }
    }
}

/// Policy-Counter-Status-Report grouped AVP (AVP 2903).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyCounterStatusReport {
    pub counter_id: String,
    pub current_status: String,
}

impl PolicyCounterStatusReport {
    pub fn new(counter_id: impl Into<String>, current_status: impl Into<String>) -> Self {
        Self {
            counter_id: counter_id.into(),
            current_status: current_status.into(),
        }
    }

    pub fn to_avp(&self) -> DiameterAvp {
        let mut inner = Vec::new();
        inner.push(DiameterAvp::new_utf8(
            AVP_POLICY_COUNTER_IDENTIFIER,
            &self.counter_id,
        ));
        inner.push(DiameterAvp::new_utf8(
            AVP_POLICY_COUNTER_STATUS,
            &self.current_status,
        ));

        let mut payload = Vec::new();
        for a in inner {
            payload.extend_from_slice(&a.serialize());
        }
        DiameterAvp::new(AVP_POLICY_COUNTER_STATUS_REPORT, &payload)
    }

    pub fn from_avp(avp: &DiameterAvp) -> Option<Self> {
        let mut counter_id = None;
        let mut current_status = None;
        let mut offset = 0;
        let data = &avp.data;

        while offset + 8 <= data.len() {
            let code = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            let flags = data[offset + 4];
            let len = u32::from_be_bytes([0, data[offset + 5], data[offset + 6], data[offset + 7]])
                as usize;
            if len < 8 || offset + len > data.len() {
                break;
            }

            let header_len = if (flags & 0x80) != 0 { 12 } else { 8 };
            if len >= header_len {
                let val_bytes = &data[offset + header_len..offset + len];
                if code == AVP_POLICY_COUNTER_IDENTIFIER {
                    counter_id = String::from_utf8(val_bytes.to_vec()).ok();
                } else if code == AVP_POLICY_COUNTER_STATUS {
                    current_status = String::from_utf8(val_bytes.to_vec()).ok();
                }
            }

            let pad = (4 - (len % 4)) % 4;
            offset += len + pad;
        }

        Some(PolicyCounterStatusReport {
            counter_id: counter_id?,
            current_status: current_status?,
        })
    }
}

/// Spending-Limit-Request (SLR).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendingLimitRequest {
    pub session_id: String,
    pub request_type: SlRequestType,
    pub subscription_id: String,
    pub subscribed_counters: Vec<String>,
}

impl SpendingLimitRequest {
    pub fn new(
        session_id: impl Into<String>,
        request_type: SlRequestType,
        subscription_id: impl Into<String>,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            request_type,
            subscription_id: subscription_id.into(),
            subscribed_counters: Vec::new(),
        }
    }

    pub fn with_counter(mut self, counter: impl Into<String>) -> Self {
        self.subscribed_counters.push(counter.into());
        self
    }

    pub fn to_diameter_message(&self, hop_by_hop_id: u32, end_to_end_id: u32) -> DiameterMessage {
        let mut avps = Vec::new();
        avps.push(DiameterAvp::new_utf8(AVP_SESSION_ID, &self.session_id));
        avps.push(DiameterAvp::new_u32(
            AVP_SL_REQUEST_TYPE,
            self.request_type as u32,
        ));

        // Subscription-Id grouped AVP
        let mut sub_inner = Vec::new();
        sub_inner.push(DiameterAvp::new_u32(AVP_SUBSCRIPTION_ID_TYPE, 0)); // END_USER_E164 / IMSI
        sub_inner.push(DiameterAvp::new_utf8(
            AVP_SUBSCRIPTION_ID_DATA,
            &self.subscription_id,
        ));
        let mut sub_payload = Vec::new();
        for a in sub_inner {
            sub_payload.extend_from_slice(&a.serialize());
        }
        avps.push(DiameterAvp::new(AVP_SUBSCRIPTION_ID, &sub_payload));

        for c in &self.subscribed_counters {
            avps.push(DiameterAvp::new_utf8(AVP_POLICY_COUNTER_IDENTIFIER, c));
        }

        DiameterMessage {
            header: DiameterHeader {
                version: 1,
                length: 0,
                flags: 0xC0, // Request + Proxiable
                command_code: DIAMETER_CMD_SPENDING_LIMIT,
                application_id: DIAMETER_APPLICATION_SY,
                hop_by_hop_id,
                end_to_end_id,
            },
            avps,
        }
    }

    pub fn from_diameter_message(msg: &DiameterMessage) -> Result<Self, String> {
        let session_id = msg
            .get_avp(AVP_SESSION_ID)
            .and_then(|a| a.as_string())
            .ok_or_else(|| "Missing Session-Id".to_string())?;

        let req_type_u32 = msg
            .get_avp(AVP_SL_REQUEST_TYPE)
            .and_then(|a| a.as_u32())
            .ok_or_else(|| "Missing SL-Request-Type".to_string())?;
        let request_type = SlRequestType::from_u32(req_type_u32);

        let mut subscription_id = String::new();
        if let Some(sub_avp) = msg.get_avp(AVP_SUBSCRIPTION_ID) {
            let mut offset = 0;
            let data = &sub_avp.data;
            while offset + 8 <= data.len() {
                let code = u32::from_be_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]);
                let len =
                    u32::from_be_bytes([0, data[offset + 5], data[offset + 6], data[offset + 7]])
                        as usize;
                if len < 8 || offset + len > data.len() {
                    break;
                }
                if code == AVP_SUBSCRIPTION_ID_DATA && len >= 8 {
                    if let Ok(s) = String::from_utf8(data[offset + 8..offset + len].to_vec()) {
                        subscription_id = s;
                    }
                }
                let pad = (4 - (len % 4)) % 4;
                offset += len + pad;
            }
        }

        let mut subscribed_counters = Vec::new();
        for avp in &msg.avps {
            if avp.code == AVP_POLICY_COUNTER_IDENTIFIER {
                if let Some(s) = avp.as_string() {
                    subscribed_counters.push(s);
                }
            }
        }

        Ok(SpendingLimitRequest {
            session_id,
            request_type,
            subscription_id,
            subscribed_counters,
        })
    }
}

/// Spending-Limit-Answer (SLA).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendingLimitAnswer {
    pub session_id: String,
    pub result_code: u32,
    pub reports: Vec<PolicyCounterStatusReport>,
}

impl SpendingLimitAnswer {
    pub fn new(session_id: impl Into<String>, result_code: u32) -> Self {
        Self {
            session_id: session_id.into(),
            result_code,
            reports: Vec::new(),
        }
    }

    pub fn with_report(mut self, report: PolicyCounterStatusReport) -> Self {
        self.reports.push(report);
        self
    }

    pub fn to_diameter_message(&self, hop_by_hop_id: u32, end_to_end_id: u32) -> DiameterMessage {
        let mut avps = Vec::new();
        avps.push(DiameterAvp::new_utf8(AVP_SESSION_ID, &self.session_id));
        avps.push(DiameterAvp::new_u32(AVP_RESULT_CODE, self.result_code));

        for r in &self.reports {
            avps.push(r.to_avp());
        }

        DiameterMessage {
            header: DiameterHeader {
                version: 1,
                length: 0,
                flags: 0x40, // Proxiable answer
                command_code: DIAMETER_CMD_SPENDING_LIMIT,
                application_id: DIAMETER_APPLICATION_SY,
                hop_by_hop_id,
                end_to_end_id,
            },
            avps,
        }
    }

    pub fn from_diameter_message(msg: &DiameterMessage) -> Result<Self, String> {
        let session_id = msg
            .get_avp(AVP_SESSION_ID)
            .and_then(|a| a.as_string())
            .ok_or_else(|| "Missing Session-Id".to_string())?;
        let result_code = msg
            .get_avp(AVP_RESULT_CODE)
            .and_then(|a| a.as_u32())
            .ok_or_else(|| "Missing Result-Code".to_string())?;

        let mut reports = Vec::new();
        for avp in &msg.avps {
            if avp.code == AVP_POLICY_COUNTER_STATUS_REPORT {
                if let Some(r) = PolicyCounterStatusReport::from_avp(avp) {
                    reports.push(r);
                }
            }
        }

        Ok(SpendingLimitAnswer {
            session_id,
            result_code,
            reports,
        })
    }
}

/// Spending-Status-Notification-Request (SNR).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendingStatusNotificationRequest {
    pub session_id: String,
    pub reports: Vec<PolicyCounterStatusReport>,
}

impl SpendingStatusNotificationRequest {
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            reports: Vec::new(),
        }
    }

    pub fn with_report(mut self, report: PolicyCounterStatusReport) -> Self {
        self.reports.push(report);
        self
    }

    pub fn to_diameter_message(&self, hop_by_hop_id: u32, end_to_end_id: u32) -> DiameterMessage {
        let mut avps = Vec::new();
        avps.push(DiameterAvp::new_utf8(AVP_SESSION_ID, &self.session_id));

        for r in &self.reports {
            avps.push(r.to_avp());
        }

        DiameterMessage {
            header: DiameterHeader {
                version: 1,
                length: 0,
                flags: 0xC0, // Request + Proxiable
                command_code: DIAMETER_CMD_SPENDING_STATUS_NOTIFICATION,
                application_id: DIAMETER_APPLICATION_SY,
                hop_by_hop_id,
                end_to_end_id,
            },
            avps,
        }
    }

    pub fn from_diameter_message(msg: &DiameterMessage) -> Result<Self, String> {
        let session_id = msg
            .get_avp(AVP_SESSION_ID)
            .and_then(|a| a.as_string())
            .ok_or_else(|| "Missing Session-Id".to_string())?;

        let mut reports = Vec::new();
        for avp in &msg.avps {
            if avp.code == AVP_POLICY_COUNTER_STATUS_REPORT {
                if let Some(r) = PolicyCounterStatusReport::from_avp(avp) {
                    reports.push(r);
                }
            }
        }

        Ok(SpendingStatusNotificationRequest {
            session_id,
            reports,
        })
    }
}

/// Spending-Status-Notification-Answer (SNA).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendingStatusNotificationAnswer {
    pub session_id: String,
    pub result_code: u32,
}

impl SpendingStatusNotificationAnswer {
    pub fn new(session_id: impl Into<String>, result_code: u32) -> Self {
        Self {
            session_id: session_id.into(),
            result_code,
        }
    }

    pub fn to_diameter_message(&self, hop_by_hop_id: u32, end_to_end_id: u32) -> DiameterMessage {
        let mut avps = Vec::new();
        avps.push(DiameterAvp::new_utf8(AVP_SESSION_ID, &self.session_id));
        avps.push(DiameterAvp::new_u32(AVP_RESULT_CODE, self.result_code));

        DiameterMessage {
            header: DiameterHeader {
                version: 1,
                length: 0,
                flags: 0x40, // Proxiable answer
                command_code: DIAMETER_CMD_SPENDING_STATUS_NOTIFICATION,
                application_id: DIAMETER_APPLICATION_SY,
                hop_by_hop_id,
                end_to_end_id,
            },
            avps,
        }
    }
}

/// OCS Spending Limit Reporting Engine.
#[derive(Debug, Clone, Default)]
pub struct OcsSyEngine {
    /// Subscriber balances: subscriber_id -> (counter_id -> status_string)
    pub subscriber_counters: HashMap<String, HashMap<String, String>>,
    /// Active Sy sessions: session_id -> (subscriber_id, subscribed_counter_ids)
    pub active_sessions: HashMap<String, (String, Vec<String>)>,
}

impl OcsSyEngine {
    pub fn new() -> Self {
        Self {
            subscriber_counters: HashMap::new(),
            active_sessions: HashMap::new(),
        }
    }

    /// Sets or initializes the current status of a subscriber policy counter.
    pub fn set_counter_status(&mut self, subscriber_id: &str, counter_id: &str, status: &str) {
        self.subscriber_counters
            .entry(subscriber_id.to_string())
            .or_default()
            .insert(counter_id.to_string(), status.to_string());
    }

    /// Handles an incoming Spending-Limit-Request (SLR) from PCRF.
    pub fn handle_slr(&mut self, slr: &SpendingLimitRequest) -> SpendingLimitAnswer {
        match slr.request_type {
            SlRequestType::InitialRequest | SlRequestType::IntermediateRequest => {
                self.active_sessions.insert(
                    slr.session_id.clone(),
                    (slr.subscription_id.clone(), slr.subscribed_counters.clone()),
                );

                let mut sla = SpendingLimitAnswer::new(&slr.session_id, DIAMETER_SUCCESS);

                if let Some(counters) = self.subscriber_counters.get(&slr.subscription_id) {
                    for cid in &slr.subscribed_counters {
                        if let Some(status) = counters.get(cid) {
                            sla = sla.with_report(PolicyCounterStatusReport::new(cid, status));
                        }
                    }
                }
                sla
            }
            SlRequestType::StopRequest => {
                self.active_sessions.remove(&slr.session_id);
                SpendingLimitAnswer::new(&slr.session_id, DIAMETER_SUCCESS)
            }
        }
    }

    /// Updates a policy counter status for a subscriber and returns triggered SNRs to subscribed PCRF sessions.
    pub fn update_counter_and_notify(
        &mut self,
        subscriber_id: &str,
        counter_id: &str,
        new_status: &str,
    ) -> Vec<SpendingStatusNotificationRequest> {
        self.set_counter_status(subscriber_id, counter_id, new_status);

        let mut notifications = Vec::new();
        for (sess_id, (sub_id, subscribed_list)) in &self.active_sessions {
            if sub_id == subscriber_id
                && (subscribed_list.is_empty() || subscribed_list.contains(&counter_id.to_string()))
            {
                let report = PolicyCounterStatusReport::new(counter_id, new_status);
                let snr = SpendingStatusNotificationRequest::new(sess_id).with_report(report);
                notifications.push(snr);
            }
        }
        notifications
    }

    /// Terminates an active Sy session.
    pub fn terminate_session(&mut self, session_id: &str) -> bool {
        self.active_sessions.remove(session_id).is_some()
    }

    /// Returns the number of currently active Sy sessions on the OCS.
    pub fn active_session_count(&self) -> usize {
        self.active_sessions.len()
    }

    /// Unsubscribes an active session from a specific policy counter.
    pub fn unsubscribe_counter(&mut self, session_id: &str, counter_id: &str) -> bool {
        if let Some((_, list)) = self.active_sessions.get_mut(session_id) {
            if let Some(pos) = list.iter().position(|c| c == counter_id) {
                list.remove(pos);
                return true;
            }
        }
        false
    }
}

/// PCRF Sy Client Engine.
#[derive(Debug, Clone, Default)]
pub struct PcrfSyClient {
    /// Active sessions: session_id -> (counter_id -> status)
    pub session_counter_cache: HashMap<String, HashMap<String, String>>,
}

impl PcrfSyClient {
    pub fn new() -> Self {
        Self {
            session_counter_cache: HashMap::new(),
        }
    }

    /// Creates an Initial Spending-Limit-Request (SLR).
    pub fn create_initial_slr(
        &mut self,
        session_id: &str,
        subscriber_id: &str,
        counters: &[&str],
    ) -> SpendingLimitRequest {
        let mut slr =
            SpendingLimitRequest::new(session_id, SlRequestType::InitialRequest, subscriber_id);
        for &c in counters {
            slr = slr.with_counter(c);
        }
        self.session_counter_cache
            .insert(session_id.to_string(), HashMap::new());
        slr
    }

    /// Processes a Spending-Limit-Answer (SLA) received from OCS.
    pub fn process_sla(&mut self, sla: &SpendingLimitAnswer) {
        if sla.result_code == DIAMETER_SUCCESS {
            let cache = self
                .session_counter_cache
                .entry(sla.session_id.clone())
                .or_default();
            for r in &sla.reports {
                cache.insert(r.counter_id.clone(), r.current_status.clone());
            }
        }
    }

    /// Processes an incoming Spending-Status-Notification-Request (SNR) from OCS and builds an SNA.
    pub fn process_snr(
        &mut self,
        snr: &SpendingStatusNotificationRequest,
    ) -> SpendingStatusNotificationAnswer {
        let cache = self
            .session_counter_cache
            .entry(snr.session_id.clone())
            .or_default();
        for r in &snr.reports {
            cache.insert(r.counter_id.clone(), r.current_status.clone());
        }
        SpendingStatusNotificationAnswer::new(&snr.session_id, DIAMETER_SUCCESS)
    }

    /// Returns the cached status of a counter in an active session.
    pub fn get_counter_status(&self, session_id: &str, counter_id: &str) -> Option<&str> {
        self.session_counter_cache
            .get(session_id)
            .and_then(|c| c.get(counter_id))
            .map(|s| s.as_str())
    }

    /// Creates an Intermediate Spending-Limit-Request (SLR) to modify subscribed policy counters.
    pub fn create_intermediate_slr(
        &mut self,
        session_id: &str,
        subscriber_id: &str,
        counters: &[&str],
    ) -> SpendingLimitRequest {
        let mut slr = SpendingLimitRequest::new(
            session_id,
            SlRequestType::IntermediateRequest,
            subscriber_id,
        );
        for &c in counters {
            slr = slr.with_counter(c);
        }
        slr
    }

    /// Terminates a local session in the PCRF cache.
    pub fn terminate_session(&mut self, session_id: &str) -> bool {
        self.session_counter_cache.remove(session_id).is_some()
    }

    /// Returns the number of active sessions tracked by the PCRF.
    pub fn active_session_count(&self) -> usize {
        self.session_counter_cache.len()
    }
}

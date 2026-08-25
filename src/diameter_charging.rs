//! Diameter Credit-Control Application & 5G Online Charging System (RFC 4006 / 3GPP TS 32.299).
//!
//! Implements Diameter Gy / Ro Credit-Control-Request (CCR) and Credit-Control-Answer (CCA)
//! messages (Command Code 272), Multiple-Services-Credit-Control (MSCC) grouped AVPs,
//! Rating Groups, quota reservation, volume metering, and Online Charging System (OCS) state.

use crate::diameter::{DiameterAvp, DiameterMessage, DIAMETER_SUCCESS};
use std::collections::HashMap;

/// Diameter Credit Control Application ID (RFC 4006 Section 3).
pub const DIAMETER_APPLICATION_CREDIT_CONTROL: u32 = 4;

/// Diameter Credit-Control Command Code (RFC 4006 Section 3).
pub const DIAMETER_CMD_CREDIT_CONTROL: u32 = 272;

/// AVP Codes for Credit-Control (RFC 4006 Section 8).
pub const AVP_CC_REQUEST_TYPE: u32 = 416;
pub const AVP_CC_REQUEST_NUMBER: u32 = 415;
pub const AVP_RATING_GROUP: u32 = 432;
pub const AVP_GRANTED_SERVICE_UNIT: u32 = 431;
pub const AVP_USED_SERVICE_UNIT: u32 = 446;
pub const AVP_CC_TOTAL_OCTETS: u32 = 421;
pub const AVP_CC_TIME: u32 = 420;
pub const AVP_MULTIPLE_SERVICES_CREDIT_CONTROL: u32 = 456;
pub const AVP_SUBSCRIPTION_ID: u32 = 443;
pub const AVP_SUBSCRIPTION_ID_DATA: u32 = 444;

/// Result Codes
pub const DIAMETER_CREDIT_LIMIT_REACHED: u32 = 4012;
pub const DIAMETER_USER_UNKNOWN: u32 = 5030;

/// CC-Request-Type values (RFC 4006 Section 8.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CcRequestType {
    InitialRequest = 1,
    UpdateRequest = 2,
    TerminationRequest = 3,
    EventRequest = 4,
}

impl CcRequestType {
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            1 => Some(CcRequestType::InitialRequest),
            2 => Some(CcRequestType::UpdateRequest),
            3 => Some(CcRequestType::TerminationRequest),
            4 => Some(CcRequestType::EventRequest),
            _ => None,
        }
    }
}

/// Service Quota Unit (Octets or Time).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ServiceQuotaUnit {
    pub total_octets: u64,
    pub time_seconds: u32,
}

/// Multiple-Services-Credit-Control (MSCC) container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsccContainer {
    pub rating_group: u32,
    pub granted_units: Option<ServiceQuotaUnit>,
    pub used_units: Option<ServiceQuotaUnit>,
    pub result_code: u32,
}

impl MsccContainer {
    pub fn new(rating_group: u32) -> Self {
        MsccContainer {
            rating_group,
            granted_units: None,
            used_units: None,
            result_code: DIAMETER_SUCCESS,
        }
    }

    /// Serializes this MSCC into grouped AVP format.
    pub fn to_avp(&self) -> DiameterAvp {
        let mut inner_avps = Vec::new();
        inner_avps.push(DiameterAvp::new_u32(AVP_RATING_GROUP, self.rating_group));
        inner_avps.push(DiameterAvp::new_u32(268, self.result_code)); // Result-Code

        if let Some(gsu) = self.granted_units {
            let mut gsu_avps = Vec::new();
            if gsu.total_octets > 0 {
                gsu_avps.push(DiameterAvp::new(
                    AVP_CC_TOTAL_OCTETS,
                    &gsu.total_octets.to_be_bytes(),
                ));
            }
            if gsu.time_seconds > 0 {
                gsu_avps.push(DiameterAvp::new_u32(AVP_CC_TIME, gsu.time_seconds));
            }
            let mut gsu_payload = Vec::new();
            for avp in gsu_avps {
                gsu_payload.extend_from_slice(&avp.serialize());
            }
            inner_avps.push(DiameterAvp::new(AVP_GRANTED_SERVICE_UNIT, &gsu_payload));
        }

        if let Some(usu) = self.used_units {
            let mut usu_avps = Vec::new();
            if usu.total_octets > 0 {
                usu_avps.push(DiameterAvp::new(
                    AVP_CC_TOTAL_OCTETS,
                    &usu.total_octets.to_be_bytes(),
                ));
            }
            let mut usu_payload = Vec::new();
            for avp in usu_avps {
                usu_payload.extend_from_slice(&avp.serialize());
            }
            inner_avps.push(DiameterAvp::new(AVP_USED_SERVICE_UNIT, &usu_payload));
        }

        let mut payload = Vec::new();
        for avp in inner_avps {
            payload.extend_from_slice(&avp.serialize());
        }
        DiameterAvp::new(AVP_MULTIPLE_SERVICES_CREDIT_CONTROL, &payload)
    }

    /// Parses an MSCC grouped AVP.
    pub fn parse_avp(avp: &DiameterAvp) -> Option<Self> {
        let mut rating_group = 0;
        let mut result_code = DIAMETER_SUCCESS;
        let mut granted_units = None;
        let mut used_units = None;

        let mut offset = 0;
        while offset < avp.data.len() {
            let (inner_avp, consumed) = DiameterAvp::parse(&avp.data[offset..])?;
            offset += consumed;

            match inner_avp.code {
                AVP_RATING_GROUP => {
                    rating_group = inner_avp.as_u32()?;
                }
                268 => {
                    result_code = inner_avp.as_u32()?;
                }
                AVP_GRANTED_SERVICE_UNIT => {
                    let mut gsu = ServiceQuotaUnit::default();
                    let mut gsu_offset = 0;
                    while gsu_offset < inner_avp.data.len() {
                        let (g_avp, g_consumed) = DiameterAvp::parse(&inner_avp.data[gsu_offset..])?;
                        gsu_offset += g_consumed;
                        if g_avp.code == AVP_CC_TOTAL_OCTETS && g_avp.data.len() >= 8 {
                            gsu.total_octets = u64::from_be_bytes(g_avp.data[..8].try_into().ok()?);
                        } else if g_avp.code == AVP_CC_TIME {
                            gsu.time_seconds = g_avp.as_u32().unwrap_or(0);
                        }
                    }
                    granted_units = Some(gsu);
                }
                AVP_USED_SERVICE_UNIT => {
                    let mut usu = ServiceQuotaUnit::default();
                    let mut usu_offset = 0;
                    while usu_offset < inner_avp.data.len() {
                        let (u_avp, u_consumed) = DiameterAvp::parse(&inner_avp.data[usu_offset..])?;
                        usu_offset += u_consumed;
                        if u_avp.code == AVP_CC_TOTAL_OCTETS && u_avp.data.len() >= 8 {
                            usu.total_octets = u64::from_be_bytes(u_avp.data[..8].try_into().ok()?);
                        }
                    }
                    used_units = Some(usu);
                }
                _ => {}
            }
        }

        Some(MsccContainer {
            rating_group,
            granted_units,
            used_units,
            result_code,
        })
    }
}

/// Credit-Control-Request (CCR) Message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditControlRequest {
    pub session_id: String,
    pub request_type: CcRequestType,
    pub request_number: u32,
    pub subscriber_id: String,
    pub mscc: Vec<MsccContainer>,
}

impl CreditControlRequest {
    pub fn new(
        session_id: &str,
        request_type: CcRequestType,
        request_number: u32,
        subscriber_id: &str,
    ) -> Self {
        CreditControlRequest {
            session_id: session_id.to_string(),
            request_type,
            request_number,
            subscriber_id: subscriber_id.to_string(),
            mscc: Vec::new(),
        }
    }

    /// Converts CCR to a standard `DiameterMessage`.
    pub fn to_diameter_message(&self, hop_by_hop_id: u32, end_to_end_id: u32) -> DiameterMessage {
        let mut msg = DiameterMessage::new_request(
            DIAMETER_CMD_CREDIT_CONTROL,
            DIAMETER_APPLICATION_CREDIT_CONTROL,
            hop_by_hop_id,
            end_to_end_id,
        );
        msg.avps.push(DiameterAvp::new_string(263, &self.session_id)); // Session-Id
        msg.avps.push(DiameterAvp::new_u32(AVP_CC_REQUEST_TYPE, self.request_type as u32));
        msg.avps.push(DiameterAvp::new_u32(AVP_CC_REQUEST_NUMBER, self.request_number));
        msg.avps.push(DiameterAvp::new_string(AVP_SUBSCRIPTION_ID_DATA, &self.subscriber_id));

        for mscc in &self.mscc {
            msg.avps.push(mscc.to_avp());
        }
        msg
    }

    /// Parses a `DiameterMessage` into a `CreditControlRequest`.
    pub fn from_diameter_message(msg: &DiameterMessage) -> Option<Self> {
        if msg.header.command_code != DIAMETER_CMD_CREDIT_CONTROL || !msg.header.is_request() {
            return None;
        }

        let session_id = msg.get_avp(263)?.as_string()?;
        let req_type_u32 = msg.get_avp(AVP_CC_REQUEST_TYPE)?.as_u32()?;
        let request_type = CcRequestType::from_u32(req_type_u32)?;
        let request_number = msg.get_avp(AVP_CC_REQUEST_NUMBER)?.as_u32()?;
        let subscriber_id = msg
            .get_avp(AVP_SUBSCRIPTION_ID_DATA)
            .and_then(|a| a.as_string())
            .unwrap_or_else(|| "unknown".to_string());

        let mut mscc_list = Vec::new();
        for avp in &msg.avps {
            if avp.code == AVP_MULTIPLE_SERVICES_CREDIT_CONTROL {
                if let Some(m) = MsccContainer::parse_avp(avp) {
                    mscc_list.push(m);
                }
            }
        }

        Some(CreditControlRequest {
            session_id,
            request_type,
            request_number,
            subscriber_id,
            mscc: mscc_list,
        })
    }
}

/// Online Charging System (OCS) Subscriber Account State.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriberAccount {
    pub subscriber_id: String,
    pub total_balance_octets: u64,
    pub granted_reserved_octets: u64,
    pub consumed_octets: u64,
    pub active_session: Option<String>,
}

/// 5G Core / Telecom Online Charging System (OCS) Engine.
#[derive(Debug, Clone, Default)]
pub struct OnlineChargingEngine {
    pub accounts: HashMap<String, SubscriberAccount>,
    pub default_grant_quota_octets: u64,
}

impl OnlineChargingEngine {
    pub fn new(default_grant_quota_octets: u64) -> Self {
        OnlineChargingEngine {
            accounts: HashMap::new(),
            default_grant_quota_octets: default_grant_quota_octets.max(1024),
        }
    }

    /// Provisions or tops up a subscriber's credit balance.
    pub fn provision_subscriber(&mut self, subscriber_id: &str, balance_octets: u64) {
        let account = self
            .accounts
            .entry(subscriber_id.to_string())
            .or_insert_with(|| SubscriberAccount {
                subscriber_id: subscriber_id.to_string(),
                total_balance_octets: 0,
                granted_reserved_octets: 0,
                consumed_octets: 0,
                active_session: None,
            });
        account.total_balance_octets += balance_octets;
    }

    /// Processes an incoming CCR and returns the corresponding CCA response.
    pub fn process_ccr(&mut self, ccr: &CreditControlRequest) -> DiameterMessage {
        let mut resp = DiameterMessage::new_answer(
            DIAMETER_CMD_CREDIT_CONTROL,
            DIAMETER_APPLICATION_CREDIT_CONTROL,
            1,
            1,
        );
        resp.avps.push(DiameterAvp::new_string(263, &ccr.session_id));
        resp.avps.push(DiameterAvp::new_u32(AVP_CC_REQUEST_TYPE, ccr.request_type as u32));
        resp.avps.push(DiameterAvp::new_u32(AVP_CC_REQUEST_NUMBER, ccr.request_number));

        let account = match self.accounts.get_mut(&ccr.subscriber_id) {
            Some(acc) => acc,
            None => {
                resp.avps.push(DiameterAvp::new_u32(268, DIAMETER_USER_UNKNOWN));
                return resp;
            }
        };

        match ccr.request_type {
            CcRequestType::InitialRequest => {
                account.active_session = Some(ccr.session_id.clone());
                let mut mscc_resp = Vec::new();
                for req_mscc in &ccr.mscc {
                    let mut ans_mscc = MsccContainer::new(req_mscc.rating_group);
                    let available = account.total_balance_octets.saturating_sub(account.granted_reserved_octets);
                    if available > 0 {
                        let grant = available.min(self.default_grant_quota_octets);
                        account.granted_reserved_octets += grant;
                        ans_mscc.granted_units = Some(ServiceQuotaUnit {
                            total_octets: grant,
                            time_seconds: 3600,
                        });
                        ans_mscc.result_code = DIAMETER_SUCCESS;
                    } else {
                        ans_mscc.result_code = DIAMETER_CREDIT_LIMIT_REACHED;
                    }
                    mscc_resp.push(ans_mscc);
                }
                resp.avps.push(DiameterAvp::new_u32(268, DIAMETER_SUCCESS));
                for m in mscc_resp {
                    resp.avps.push(m.to_avp());
                }
            }
            CcRequestType::UpdateRequest => {
                for req_mscc in &ccr.mscc {
                    if let Some(used) = req_mscc.used_units {
                        let used_octets = used.total_octets;
                        account.consumed_octets += used_octets;
                        account.total_balance_octets = account.total_balance_octets.saturating_sub(used_octets);
                        account.granted_reserved_octets = account.granted_reserved_octets.saturating_sub(used_octets);
                    }
                }
                let mut mscc_resp = Vec::new();
                for req_mscc in &ccr.mscc {
                    let mut ans_mscc = MsccContainer::new(req_mscc.rating_group);
                    let available = account.total_balance_octets.saturating_sub(account.granted_reserved_octets);
                    if available > 0 {
                        let grant = available.min(self.default_grant_quota_octets);
                        account.granted_reserved_octets += grant;
                        ans_mscc.granted_units = Some(ServiceQuotaUnit {
                            total_octets: grant,
                            time_seconds: 3600,
                        });
                        ans_mscc.result_code = DIAMETER_SUCCESS;
                    } else {
                        ans_mscc.result_code = DIAMETER_CREDIT_LIMIT_REACHED;
                    }
                    mscc_resp.push(ans_mscc);
                }
                resp.avps.push(DiameterAvp::new_u32(268, DIAMETER_SUCCESS));
                for m in mscc_resp {
                    resp.avps.push(m.to_avp());
                }
            }
            CcRequestType::TerminationRequest => {
                for req_mscc in &ccr.mscc {
                    if let Some(used) = req_mscc.used_units {
                        let used_octets = used.total_octets;
                        account.consumed_octets += used_octets;
                        account.total_balance_octets = account.total_balance_octets.saturating_sub(used_octets);
                    }
                }
                account.granted_reserved_octets = 0;
                account.active_session = None;
                resp.avps.push(DiameterAvp::new_u32(268, DIAMETER_SUCCESS));
            }
            CcRequestType::EventRequest => {
                resp.avps.push(DiameterAvp::new_u32(268, DIAMETER_SUCCESS));
            }
        }

        resp
    }
}

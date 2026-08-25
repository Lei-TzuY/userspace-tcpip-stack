//! 3GPP Diameter Rx Interface & IMS/5G Policy and Charging Control (3GPP TS 29.214 / TS 23.203).
//!
//! Implements Policy and Charging Control (PCC) signalling between the Application Function (AF / P-CSCF)
//! and Policy and Charging Rules Function (PCRF / PCF) over Diameter Application ID 16777236.
//! Supports AA-Request/Answer (AAR/AAA - Command 265), Session Termination (STR/STA - Command 275),
//! dynamic Media-Component-Description grouped AVPs, Flow-Description IPFilterRules, and QCI bearer authorization.

use crate::diameter::{DIAMETER_SUCCESS, DiameterAvp, DiameterMessage};
use std::collections::HashMap;

/// Diameter Rx Application ID (3GPP TS 29.214 Section 5.1).
pub const DIAMETER_APPLICATION_RX: u32 = 16777236;

/// Command Codes for Diameter Rx.
pub const DIAMETER_CMD_AA: u32 = 265; // AAR / AAA
pub const DIAMETER_CMD_SESSION_TERMINATION: u32 = 275; // STR / STA
pub const DIAMETER_CMD_ABORT_SESSION: u32 = 274; // ASR / ASA

/// Rx AVP Codes (3GPP TS 29.214 Section 5.3).
pub const AVP_ABORT_CAUSE: u32 = 500;
pub const AVP_AF_APPLICATION_IDENTIFIER: u32 = 504;
pub const AVP_FLOW_DESCRIPTION: u32 = 507;
pub const AVP_FLOW_NUMBER: u32 = 509;
pub const AVP_FLOW_STATUS: u32 = 511;
pub const AVP_FLOW_USAGE: u32 = 512;
pub const AVP_SPECIFIC_ACTION: u32 = 513;
pub const AVP_MAX_REQUESTED_BANDWIDTH_DL: u32 = 515;
pub const AVP_MAX_REQUESTED_BANDWIDTH_UL: u32 = 516;
pub const AVP_MEDIA_COMPONENT_DESCRIPTION: u32 = 517;
pub const AVP_MEDIA_COMPONENT_NUMBER: u32 = 518;
pub const AVP_MEDIA_SUB_COMPONENT: u32 = 519;
pub const AVP_MEDIA_TYPE: u32 = 520;
pub const AVP_SERVICE_INFO_STATUS: u32 = 527;

/// Media-Type values (AVP 520).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaType {
    Audio = 0,
    Video = 1,
    Data = 2,
    Application = 3,
    Control = 4,
    Text = 5,
    Message = 6,
    Other = 7,
}

impl MediaType {
    pub fn from_u32(v: u32) -> Self {
        match v {
            0 => MediaType::Audio,
            1 => MediaType::Video,
            2 => MediaType::Data,
            3 => MediaType::Application,
            4 => MediaType::Control,
            5 => MediaType::Text,
            6 => MediaType::Message,
            _ => MediaType::Other,
        }
    }
}

/// Media-Sub-Component grouped AVP (AVP 519).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaSubComponent {
    pub flow_number: u32,
    pub flow_descriptions: Vec<String>,
    pub flow_status: u32, // 0=Disabled, 1=Enabled-Uplink, 2=Enabled-Downlink, 3=Enabled
    pub flow_usage: u32,  // 0=No-Information, 1=RTCP
}

impl MediaSubComponent {
    pub fn new(flow_number: u32) -> Self {
        MediaSubComponent {
            flow_number,
            flow_descriptions: Vec::new(),
            flow_status: 3, // Enabled
            flow_usage: 0,
        }
    }

    pub fn to_avp(&self) -> DiameterAvp {
        let mut inner = Vec::new();
        inner.push(DiameterAvp::new_u32(AVP_FLOW_NUMBER, self.flow_number));
        for fd in &self.flow_descriptions {
            inner.push(DiameterAvp::new_utf8(AVP_FLOW_DESCRIPTION, fd));
        }
        inner.push(DiameterAvp::new_u32(AVP_FLOW_STATUS, self.flow_status));
        inner.push(DiameterAvp::new_u32(AVP_FLOW_USAGE, self.flow_usage));

        let mut payload = Vec::new();
        for a in inner {
            payload.extend_from_slice(&a.serialize());
        }
        DiameterAvp::new(AVP_MEDIA_SUB_COMPONENT, &payload)
    }

    pub fn parse_avp(avp: &DiameterAvp) -> Option<Self> {
        let mut offset = 0;
        let mut flow_number = 1;
        let mut flow_descriptions = Vec::new();
        let mut flow_status = 3;
        let mut flow_usage = 0;

        while offset < avp.data.len() {
            let (child, consumed) = DiameterAvp::parse(&avp.data[offset..])?;
            match child.code {
                AVP_FLOW_NUMBER => flow_number = child.as_u32().unwrap_or(1),
                AVP_FLOW_DESCRIPTION => {
                    if let Some(s) = child.as_string() {
                        flow_descriptions.push(s);
                    }
                }
                AVP_FLOW_STATUS => flow_status = child.as_u32().unwrap_or(3),
                AVP_FLOW_USAGE => flow_usage = child.as_u32().unwrap_or(0),
                _ => {}
            }
            offset += consumed;
        }

        Some(MediaSubComponent {
            flow_number,
            flow_descriptions,
            flow_status,
            flow_usage,
        })
    }
}

/// Media-Component-Description grouped AVP (AVP 517).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaComponentDescription {
    pub component_number: u32,
    pub media_type: MediaType,
    pub max_bandwidth_ul: u32, // bps
    pub max_bandwidth_dl: u32, // bps
    pub sub_components: Vec<MediaSubComponent>,
}

impl MediaComponentDescription {
    pub fn new(component_number: u32, media_type: MediaType) -> Self {
        MediaComponentDescription {
            component_number,
            media_type,
            max_bandwidth_ul: 64_000,
            max_bandwidth_dl: 64_000,
            sub_components: Vec::new(),
        }
    }

    pub fn to_avp(&self) -> DiameterAvp {
        let mut inner = Vec::new();
        inner.push(DiameterAvp::new_u32(
            AVP_MEDIA_COMPONENT_NUMBER,
            self.component_number,
        ));
        inner.push(DiameterAvp::new_u32(AVP_MEDIA_TYPE, self.media_type as u32));
        if self.max_bandwidth_ul > 0 {
            inner.push(DiameterAvp::new_u32(
                AVP_MAX_REQUESTED_BANDWIDTH_UL,
                self.max_bandwidth_ul,
            ));
        }
        if self.max_bandwidth_dl > 0 {
            inner.push(DiameterAvp::new_u32(
                AVP_MAX_REQUESTED_BANDWIDTH_DL,
                self.max_bandwidth_dl,
            ));
        }
        for sub in &self.sub_components {
            inner.push(sub.to_avp());
        }

        let mut payload = Vec::new();
        for a in inner {
            payload.extend_from_slice(&a.serialize());
        }
        DiameterAvp::new(AVP_MEDIA_COMPONENT_DESCRIPTION, &payload)
    }

    pub fn parse_avp(avp: &DiameterAvp) -> Option<Self> {
        let mut offset = 0;
        let mut component_number = 1;
        let mut media_type = MediaType::Audio;
        let mut max_bandwidth_ul = 0;
        let mut max_bandwidth_dl = 0;
        let mut sub_components = Vec::new();

        while offset < avp.data.len() {
            let (child, consumed) = DiameterAvp::parse(&avp.data[offset..])?;
            match child.code {
                AVP_MEDIA_COMPONENT_NUMBER => component_number = child.as_u32().unwrap_or(1),
                AVP_MEDIA_TYPE => media_type = MediaType::from_u32(child.as_u32().unwrap_or(0)),
                AVP_MAX_REQUESTED_BANDWIDTH_UL => max_bandwidth_ul = child.as_u32().unwrap_or(0),
                AVP_MAX_REQUESTED_BANDWIDTH_DL => max_bandwidth_dl = child.as_u32().unwrap_or(0),
                AVP_MEDIA_SUB_COMPONENT => {
                    if let Some(sub) = MediaSubComponent::parse_avp(&child) {
                        sub_components.push(sub);
                    }
                }
                _ => {}
            }
            offset += consumed;
        }

        Some(MediaComponentDescription {
            component_number,
            media_type,
            max_bandwidth_ul,
            max_bandwidth_dl,
            sub_components,
        })
    }
}

/// AA-Request (AAR) message structure for Diameter Rx (Command 265).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AaRequest {
    pub session_id: String,
    pub af_application_identifier: String,
    pub service_info_status: u32,
    pub media_components: Vec<MediaComponentDescription>,
}

impl AaRequest {
    pub fn new(session_id: &str, af_app_id: &str) -> Self {
        AaRequest {
            session_id: session_id.to_string(),
            af_application_identifier: af_app_id.to_string(),
            service_info_status: 0, // Final
            media_components: Vec::new(),
        }
    }

    pub fn to_diameter_message(&self, hop_id: u32, end_id: u32) -> DiameterMessage {
        let mut msg =
            DiameterMessage::new_request(DIAMETER_CMD_AA, DIAMETER_APPLICATION_RX, hop_id, end_id);
        msg.avps.push(DiameterAvp::new_utf8(263, &self.session_id)); // Session-Id
        msg.avps.push(DiameterAvp::new_utf8(
            AVP_AF_APPLICATION_IDENTIFIER,
            &self.af_application_identifier,
        ));
        msg.avps.push(DiameterAvp::new_u32(
            AVP_SERVICE_INFO_STATUS,
            self.service_info_status,
        ));
        for mc in &self.media_components {
            msg.avps.push(mc.to_avp());
        }
        msg
    }

    pub fn from_diameter_message(msg: &DiameterMessage) -> Option<Self> {
        let session_id = msg
            .get_avp(263)
            .and_then(|a| a.as_string())
            .unwrap_or_default();
        let af_app_id = msg
            .get_avp(AVP_AF_APPLICATION_IDENTIFIER)
            .and_then(|a| a.as_string())
            .unwrap_or_default();
        let service_info_status = msg
            .get_avp(AVP_SERVICE_INFO_STATUS)
            .and_then(|a| a.as_u32())
            .unwrap_or(0);

        let mut media_components = Vec::new();
        for avp in &msg.avps {
            if avp.code == AVP_MEDIA_COMPONENT_DESCRIPTION {
                if let Some(mc) = MediaComponentDescription::parse_avp(avp) {
                    media_components.push(mc);
                }
            }
        }

        Some(AaRequest {
            session_id,
            af_application_identifier: af_app_id,
            service_info_status,
            media_components,
        })
    }
}

/// Policy & Charging Control (PCC) Authorized Session State.
#[derive(Debug, Clone)]
pub struct PcrfSessionState {
    pub session_id: String,
    pub af_application_identifier: String,
    pub authorized_qci: u8,
    pub granted_bandwidth_ul_bps: u32,
    pub granted_bandwidth_dl_bps: u32,
    pub is_active: bool,
}

/// Simulated PCRF (Policy and Charging Rules Function) Rx Server Engine.
#[derive(Debug, Clone)]
pub struct PcrfRxEngine {
    pub total_capacity_bps: u64,
    pub allocated_bandwidth_bps: u64,
    pub sessions: HashMap<String, PcrfSessionState>,
}

impl PcrfRxEngine {
    pub fn new(total_capacity_bps: u64) -> Self {
        PcrfRxEngine {
            total_capacity_bps,
            allocated_bandwidth_bps: 0,
            sessions: HashMap::new(),
        }
    }

    /// Processes an AA-Request from an AF (e.g., IMS P-CSCF) and authorizes QoS & Bearers.
    pub fn process_aar(&mut self, req: &AaRequest) -> DiameterMessage {
        let mut total_req_ul = 0u32;
        let mut total_req_dl = 0u32;
        let mut highest_qci = 9u8; // Default Best Effort (QCI 9)

        for mc in &req.media_components {
            total_req_ul += mc.max_bandwidth_ul;
            total_req_dl += mc.max_bandwidth_dl;

            match mc.media_type {
                MediaType::Audio => {
                    // Conversational Voice -> QCI 1 (Highest priority GBR)
                    if highest_qci > 1 {
                        highest_qci = 1;
                    }
                }
                MediaType::Video => {
                    // Conversational Video -> QCI 2 (GBR)
                    if highest_qci > 2 {
                        highest_qci = 2;
                    }
                }
                MediaType::Control => {
                    // IMS Signalling -> QCI 5
                    if highest_qci > 5 {
                        highest_qci = 5;
                    }
                }
                _ => {}
            }
        }

        let needed_bw = (total_req_ul as u64) + (total_req_dl as u64);
        let current_session_bw = self
            .sessions
            .get(&req.session_id)
            .map(|s| (s.granted_bandwidth_ul_bps as u64) + (s.granted_bandwidth_dl_bps as u64))
            .unwrap_or(0);

        if self.allocated_bandwidth_bps - current_session_bw + needed_bw > self.total_capacity_bps {
            // Insufficient resources -> DIAMETER_UNABLE_TO_COMPLY (5012)
            let mut ans =
                DiameterMessage::new_answer(DIAMETER_CMD_AA, DIAMETER_APPLICATION_RX, 0, 0);
            ans.avps.push(DiameterAvp::new_utf8(263, &req.session_id));
            ans.avps.push(DiameterAvp::new_u32(268, 5012)); // Result-Code
            return ans;
        }

        // Commit bandwidth reservation
        self.allocated_bandwidth_bps =
            self.allocated_bandwidth_bps - current_session_bw + needed_bw;
        self.sessions.insert(
            req.session_id.clone(),
            PcrfSessionState {
                session_id: req.session_id.clone(),
                af_application_identifier: req.af_application_identifier.clone(),
                authorized_qci: highest_qci,
                granted_bandwidth_ul_bps: total_req_ul,
                granted_bandwidth_dl_bps: total_req_dl,
                is_active: true,
            },
        );

        let mut ans = DiameterMessage::new_answer(DIAMETER_CMD_AA, DIAMETER_APPLICATION_RX, 0, 0);
        ans.avps.push(DiameterAvp::new_utf8(263, &req.session_id));
        ans.avps.push(DiameterAvp::new_u32(268, DIAMETER_SUCCESS)); // 2001
        ans.avps.push(DiameterAvp::new_u32(
            AVP_SPECIFIC_ACTION,
            highest_qci as u32,
        )); // Authorized QCI

        ans
    }

    /// Processes a Session-Termination-Request (STR).
    pub fn process_str(&mut self, session_id: &str) -> DiameterMessage {
        if let Some(s) = self.sessions.remove(session_id) {
            let session_bw =
                (s.granted_bandwidth_ul_bps as u64) + (s.granted_bandwidth_dl_bps as u64);
            self.allocated_bandwidth_bps = self.allocated_bandwidth_bps.saturating_sub(session_bw);
        }

        let mut ans = DiameterMessage::new_answer(
            DIAMETER_CMD_SESSION_TERMINATION,
            DIAMETER_APPLICATION_RX,
            0,
            0,
        );
        ans.avps.push(DiameterAvp::new_utf8(263, session_id));
        ans.avps.push(DiameterAvp::new_u32(268, DIAMETER_SUCCESS));
        ans
    }
}

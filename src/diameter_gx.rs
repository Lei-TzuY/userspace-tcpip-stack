//! 3GPP Diameter Gx Policy and Charging Control (PCC) Interface (3GPP TS 29.212).
//!
//! Implements the Diameter Gx interface between PCRF (Policy and Charging Rules Function)
//! and PCEF (Policy and Charging Enforcement Function / PGW / SMF) over Application ID 16777238.
//! Supports dynamic PCC rule installation, QoS-Information, Flow-Information filters, and traffic gating.

use crate::diameter::{
    DIAMETER_FLAG_MANDATORY, DIAMETER_FLAG_VENDOR_SPECIFIC, DIAMETER_SUCCESS, DiameterAvp,
    DiameterMessage,
};
use crate::diameter_charging::CcRequestType;
use std::collections::HashMap;

/// Diameter Application ID for 3GPP Gx Interface (3GPP TS 29.212).
pub const DIAMETER_APPLICATION_GX: u32 = 16777238;

/// Diameter Command Code for Credit-Control / Policy-Control (CCR / CCA).
pub const DIAMETER_CMD_CC: u32 = 272;
/// Diameter Command Code for Re-Auth (RAR / RAA).
pub const DIAMETER_CMD_RE_AUTH: u32 = 258;

/// Standard 3GPP Gx AVP Codes (Vendor ID = 10415).
pub const AVP_CHARGING_RULE_INSTALL: u32 = 1001;
pub const AVP_CHARGING_RULE_REMOVE: u32 = 1002;
pub const AVP_CHARGING_RULE_DEFINITION: u32 = 1003;
pub const AVP_CHARGING_RULE_NAME: u32 = 1005;
pub const AVP_EVENT_TRIGGER: u32 = 1006;
pub const AVP_QOS_INFORMATION: u32 = 1016;
pub const AVP_IP_CAN_TYPE: u32 = 1027;
pub const AVP_QOS_CLASS_IDENTIFIER: u32 = 1028;
pub const AVP_FLOW_INFORMATION: u32 = 1058;
pub const AVP_FLOW_DESCRIPTION: u32 = 507;
pub const AVP_FLOW_STATUS: u32 = 511;
pub const AVP_MAX_REQUESTED_BANDWIDTH_UL: u32 = 516;
pub const AVP_MAX_REQUESTED_BANDWIDTH_DL: u32 = 515;
pub const AVP_FLOW_DIRECTION: u32 = 1080;
pub const AVP_PRE_EMPTION_CAPABILITY: u32 = 1047;
pub const AVP_PRE_EMPTION_VULNERABILITY: u32 = 1048;

/// 3GPP Vendor ID (10415).
pub const VENDOR_3GPP: u32 = 10415;

/// IP-CAN Type enumeration (3GPP TS 29.212).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpCanType {
    ThreeGppGprs = 0,
    ThreeGppEps = 5,
    ThreeGpp5Gs = 7,
    NonThreeGpp = 10,
}

impl IpCanType {
    pub fn from_u32(val: u32) -> Self {
        match val {
            0 => IpCanType::ThreeGppGprs,
            5 => IpCanType::ThreeGppEps,
            7 => IpCanType::ThreeGpp5Gs,
            _ => IpCanType::NonThreeGpp,
        }
    }
}

/// A dynamic Policy and Charging Control (PCC) Rule installed on the PCEF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PccRule {
    pub rule_name: String,
    pub flow_descriptions: Vec<String>,
    pub qci: u32,
    pub max_bandwidth_ul_bps: u32,
    pub max_bandwidth_dl_bps: u32,
    pub precedence: u32,
    pub gate_enabled: bool,
}

impl PccRule {
    pub fn new(rule_name: &str, qci: u32, bw_ul: u32, bw_dl: u32) -> Self {
        PccRule {
            rule_name: rule_name.to_string(),
            flow_descriptions: Vec::new(),
            qci,
            max_bandwidth_ul_bps: bw_ul,
            max_bandwidth_dl_bps: bw_dl,
            precedence: 100,
            gate_enabled: true,
        }
    }

    /// Serializes this PCC rule as a `Charging-Rule-Definition` Grouped AVP.
    pub fn to_grouped_avp(&self) -> DiameterAvp {
        let mut inner_avps = Vec::new();

        // 1. Charging-Rule-Name (AVP 1005)
        inner_avps.push(DiameterAvp::new_vendor(
            AVP_CHARGING_RULE_NAME,
            DIAMETER_FLAG_MANDATORY | DIAMETER_FLAG_VENDOR_SPECIFIC,
            VENDOR_3GPP,
            self.rule_name.as_bytes(),
        ));

        // 2. Flow-Information (AVP 1058)
        for flow in &self.flow_descriptions {
            let desc_avp = DiameterAvp::new_vendor(
                AVP_FLOW_DESCRIPTION,
                DIAMETER_FLAG_MANDATORY | DIAMETER_FLAG_VENDOR_SPECIFIC,
                VENDOR_3GPP,
                flow.as_bytes(),
            );
            inner_avps.push(DiameterAvp::new_vendor(
                AVP_FLOW_INFORMATION,
                DIAMETER_FLAG_MANDATORY | DIAMETER_FLAG_VENDOR_SPECIFIC,
                VENDOR_3GPP,
                &desc_avp.serialize(),
            ));
        }

        // 3. QoS-Information (AVP 1016)
        let mut qos_avps = Vec::new();
        qos_avps.push(DiameterAvp::new_vendor(
            AVP_QOS_CLASS_IDENTIFIER,
            DIAMETER_FLAG_MANDATORY | DIAMETER_FLAG_VENDOR_SPECIFIC,
            VENDOR_3GPP,
            &self.qci.to_be_bytes(),
        ));
        qos_avps.push(DiameterAvp::new_vendor(
            AVP_MAX_REQUESTED_BANDWIDTH_UL,
            DIAMETER_FLAG_MANDATORY | DIAMETER_FLAG_VENDOR_SPECIFIC,
            VENDOR_3GPP,
            &self.max_bandwidth_ul_bps.to_be_bytes(),
        ));
        qos_avps.push(DiameterAvp::new_vendor(
            AVP_MAX_REQUESTED_BANDWIDTH_DL,
            DIAMETER_FLAG_MANDATORY | DIAMETER_FLAG_VENDOR_SPECIFIC,
            VENDOR_3GPP,
            &self.max_bandwidth_dl_bps.to_be_bytes(),
        ));

        let mut qos_data = Vec::new();
        for a in qos_avps {
            qos_data.extend_from_slice(&a.serialize());
        }
        inner_avps.push(DiameterAvp::new_vendor(
            AVP_QOS_INFORMATION,
            DIAMETER_FLAG_MANDATORY | DIAMETER_FLAG_VENDOR_SPECIFIC,
            VENDOR_3GPP,
            &qos_data,
        ));

        let mut def_data = Vec::new();
        for a in inner_avps {
            def_data.extend_from_slice(&a.serialize());
        }
        DiameterAvp::new_vendor(
            AVP_CHARGING_RULE_DEFINITION,
            DIAMETER_FLAG_MANDATORY | DIAMETER_FLAG_VENDOR_SPECIFIC,
            VENDOR_3GPP,
            &def_data,
        )
    }

    /// Parses a `Charging-Rule-Definition` Grouped AVP into a `PccRule`.
    pub fn from_grouped_avp(avp: &DiameterAvp) -> Option<Self> {
        let mut rule_name = String::new();
        let mut flows = Vec::new();
        let mut qci = 9;
        let mut bw_ul = 0;
        let mut bw_dl = 0;

        let inner_avps = DiameterAvp::parse_all(&avp.data);
        for inner in inner_avps {
            match inner.code {
                AVP_CHARGING_RULE_NAME => {
                    rule_name = String::from_utf8_lossy(&inner.data).to_string();
                }
                AVP_FLOW_INFORMATION => {
                    let flow_inners = DiameterAvp::parse_all(&inner.data);
                    for f in flow_inners {
                        if f.code == AVP_FLOW_DESCRIPTION {
                            flows.push(String::from_utf8_lossy(&f.data).to_string());
                        }
                    }
                }
                AVP_QOS_INFORMATION => {
                    let qos_inners = DiameterAvp::parse_all(&inner.data);
                    for q in qos_inners {
                        match q.code {
                            AVP_QOS_CLASS_IDENTIFIER => {
                                qci = q.as_u32().unwrap_or(9);
                            }
                            AVP_MAX_REQUESTED_BANDWIDTH_UL => {
                                bw_ul = q.as_u32().unwrap_or(0);
                            }
                            AVP_MAX_REQUESTED_BANDWIDTH_DL => {
                                bw_dl = q.as_u32().unwrap_or(0);
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }

        if rule_name.is_empty() {
            None
        } else {
            Some(PccRule {
                rule_name,
                flow_descriptions: flows,
                qci,
                max_bandwidth_ul_bps: bw_ul,
                max_bandwidth_dl_bps: bw_dl,
                precedence: 100,
                gate_enabled: true,
            })
        }
    }
}

/// Diameter Gx Credit-Control-Request (CCR) sent by PCEF to PCRF.
#[derive(Debug, Clone)]
pub struct GxCreditControlRequest {
    pub session_id: String,
    pub cc_request_type: CcRequestType,
    pub cc_request_number: u32,
    pub subscription_id: String,
    pub ip_can_type: IpCanType,
}

impl GxCreditControlRequest {
    pub fn new(
        session_id: &str,
        req_type: CcRequestType,
        req_num: u32,
        sub_id: &str,
        ip_can: IpCanType,
    ) -> Self {
        GxCreditControlRequest {
            session_id: session_id.to_string(),
            cc_request_type: req_type,
            cc_request_number: req_num,
            subscription_id: sub_id.to_string(),
            ip_can_type: ip_can,
        }
    }

    pub fn to_diameter_message(&self, hop_by_hop: u32, end_to_end: u32) -> DiameterMessage {
        let mut msg = DiameterMessage::new_request(
            DIAMETER_CMD_CC,
            DIAMETER_APPLICATION_GX,
            hop_by_hop,
            end_to_end,
        );
        msg.add_avp(DiameterAvp::new_utf8(263, &self.session_id));
        msg.add_avp(DiameterAvp::new_u32(416, self.cc_request_type as u32));
        msg.add_avp(DiameterAvp::new_u32(415, self.cc_request_number));
        msg.add_avp(DiameterAvp::new_utf8(443, &self.subscription_id));
        msg.add_avp(DiameterAvp::new_vendor(
            AVP_IP_CAN_TYPE,
            DIAMETER_FLAG_MANDATORY | DIAMETER_FLAG_VENDOR_SPECIFIC,
            VENDOR_3GPP,
            &(self.ip_can_type as u32).to_be_bytes(),
        ));
        msg
    }
}

/// PCEF Policy and Charging Enforcement Function Engine (PGW / SMF / UPF Controller).
#[derive(Debug, Clone)]
pub struct PcefGxEngine {
    pub pcrf_realm: String,
    pub active_sessions: HashMap<String, String>, // Session ID -> Subscriber IMSI
    pub installed_rules: HashMap<String, Vec<PccRule>>, // Session ID -> [Installed PCC Rules]
    pub total_enforced_bytes: u64,
}

impl PcefGxEngine {
    pub fn new(pcrf_realm: &str) -> Self {
        PcefGxEngine {
            pcrf_realm: pcrf_realm.to_string(),
            active_sessions: HashMap::new(),
            installed_rules: HashMap::new(),
            total_enforced_bytes: 0,
        }
    }

    /// Handles a Gx Initial CCR, binds subscriber, and applies default Internet and IMS rules.
    pub fn handle_session_establishment(
        &mut self,
        session_id: &str,
        subscriber_id: &str,
        ip_can: IpCanType,
    ) -> DiameterMessage {
        self.active_sessions
            .insert(session_id.to_string(), subscriber_id.to_string());

        let mut default_rules = Vec::new();
        // Default Internet Best-Effort Rule (QCI 9)
        let mut r_default = PccRule::new("rule-default-internet", 9, 20_000_000, 100_000_000);
        r_default
            .flow_descriptions
            .push("permit out ip from any to any".to_string());
        default_rules.push(r_default);

        // If 5GS or EPS, provision IMS Signalling Rule (QCI 5)
        if ip_can == IpCanType::ThreeGpp5Gs || ip_can == IpCanType::ThreeGppEps {
            let mut r_ims = PccRule::new("rule-ims-signalling", 5, 512_000, 512_000);
            r_ims
                .flow_descriptions
                .push("permit out udp from any to 10.0.0.1 5060".to_string());
            default_rules.push(r_ims);
        }

        self.installed_rules
            .insert(session_id.to_string(), default_rules.clone());

        // Construct Gx Credit-Control-Answer (CCA)
        let mut cca = DiameterMessage::new_answer(DIAMETER_CMD_CC, DIAMETER_APPLICATION_GX, 1, 1);
        cca.add_avp(DiameterAvp::new_utf8(263, session_id));
        cca.add_avp(DiameterAvp::new_u32(268, DIAMETER_SUCCESS));
        cca.add_avp(DiameterAvp::new_u32(
            416,
            CcRequestType::InitialRequest as u32,
        ));

        // Install rules in CCA
        for rule in &default_rules {
            let def_avp = rule.to_grouped_avp();
            cca.add_avp(DiameterAvp::new_vendor(
                AVP_CHARGING_RULE_INSTALL,
                DIAMETER_FLAG_MANDATORY | DIAMETER_FLAG_VENDOR_SPECIFIC,
                VENDOR_3GPP,
                &def_avp.serialize(),
            ));
        }

        cca
    }

    /// Dynamically installs an additional PCC Rule (e.g. VoLTE Voice QCI 1 triggered via Rx).
    pub fn install_rule(&mut self, session_id: &str, rule: PccRule) -> bool {
        if let Some(rules) = self.installed_rules.get_mut(session_id) {
            rules.retain(|r| r.rule_name != rule.rule_name);
            rules.push(rule);
            true
        } else {
            false
        }
    }

    /// Removes a PCC Rule by name.
    pub fn remove_rule(&mut self, session_id: &str, rule_name: &str) -> bool {
        if let Some(rules) = self.installed_rules.get_mut(session_id) {
            let initial = rules.len();
            rules.retain(|r| r.rule_name != rule_name);
            rules.len() < initial
        } else {
            false
        }
    }

    /// Terminates a Gx session and flushes all installed PCC rules.
    pub fn handle_session_termination(&mut self, session_id: &str) -> bool {
        self.installed_rules.remove(session_id);
        self.active_sessions.remove(session_id).is_some()
    }

    /// Handles a Gx Re-Auth-Request (RAR) from PCRF, applying rule installations and removals.
    pub fn handle_rar(
        &mut self,
        rar: &GxReAuthRequest,
        local_host: &str,
        local_realm: &str,
    ) -> GxReAuthAnswer {
        if !self.active_sessions.contains_key(&rar.session_id) {
            return GxReAuthAnswer {
                session_id: rar.session_id.clone(),
                result_code: 5002, // DIAMETER_UNKNOWN_SESSION_ID
                origin_host: local_host.to_string(),
                origin_realm: local_realm.to_string(),
            };
        }

        // Apply rule removals
        for r_name in &rar.rules_to_remove {
            self.remove_rule(&rar.session_id, r_name);
        }

        // Apply rule installations
        for rule in &rar.rules_to_install {
            self.install_rule(&rar.session_id, rule.clone());
        }

        GxReAuthAnswer {
            session_id: rar.session_id.clone(),
            result_code: DIAMETER_SUCCESS,
            origin_host: local_host.to_string(),
            origin_realm: local_realm.to_string(),
        }
    }

    /// Evaluates incoming/outgoing IP traffic against installed PCC rules for a session.
    ///
    /// Matches flow description substring and verifies the gate is enabled.
    pub fn enforce_traffic(
        &mut self,
        session_id: &str,
        flow_str: &str,
        byte_len: u64,
    ) -> Option<PccRule> {
        let rules = self.installed_rules.get(session_id)?;
        for rule in rules {
            if rule.gate_enabled {
                for fd in &rule.flow_descriptions {
                    if fd.contains("any to any") || flow_str.contains(fd) || fd.contains(flow_str) {
                        self.total_enforced_bytes += byte_len;
                        return Some(rule.clone());
                    }
                }
            }
        }
        None
    }
}

/// Diameter Gx Re-Auth-Request (RAR) sent by PCRF to PCEF (3GPP TS 29.212 Section 5.6.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GxReAuthRequest {
    pub session_id: String,
    pub origin_host: String,
    pub origin_realm: String,
    pub destination_host: String,
    pub destination_realm: String,
    pub rules_to_install: Vec<PccRule>,
    pub rules_to_remove: Vec<String>,
    pub event_triggers: Vec<u32>,
}

impl GxReAuthRequest {
    pub fn to_diameter_message(&self, hop_by_hop: u32, end_to_end: u32) -> DiameterMessage {
        let mut msg = DiameterMessage::new_request(
            DIAMETER_CMD_RE_AUTH,
            DIAMETER_APPLICATION_GX,
            hop_by_hop,
            end_to_end,
        );
        msg.add_avp(DiameterAvp::new_utf8(263, &self.session_id));
        msg.add_avp(DiameterAvp::new_utf8(264, &self.origin_host));
        msg.add_avp(DiameterAvp::new_utf8(296, &self.origin_realm));
        msg.add_avp(DiameterAvp::new_utf8(293, &self.destination_host));
        msg.add_avp(DiameterAvp::new_utf8(283, &self.destination_realm));

        for rule in &self.rules_to_install {
            let def_avp = rule.to_grouped_avp();
            msg.add_avp(DiameterAvp::new_vendor(
                AVP_CHARGING_RULE_INSTALL,
                DIAMETER_FLAG_MANDATORY | DIAMETER_FLAG_VENDOR_SPECIFIC,
                VENDOR_3GPP,
                &def_avp.serialize(),
            ));
        }

        for r_name in &self.rules_to_remove {
            let name_avp = DiameterAvp::new_vendor(
                AVP_CHARGING_RULE_NAME,
                DIAMETER_FLAG_MANDATORY | DIAMETER_FLAG_VENDOR_SPECIFIC,
                VENDOR_3GPP,
                r_name.as_bytes(),
            );
            msg.add_avp(DiameterAvp::new_vendor(
                AVP_CHARGING_RULE_REMOVE,
                DIAMETER_FLAG_MANDATORY | DIAMETER_FLAG_VENDOR_SPECIFIC,
                VENDOR_3GPP,
                &name_avp.serialize(),
            ));
        }

        for &trig in &self.event_triggers {
            msg.add_avp(DiameterAvp::new_vendor(
                AVP_EVENT_TRIGGER,
                DIAMETER_FLAG_MANDATORY | DIAMETER_FLAG_VENDOR_SPECIFIC,
                VENDOR_3GPP,
                &trig.to_be_bytes(),
            ));
        }
        msg
    }

    pub fn from_diameter_message(msg: &DiameterMessage) -> Option<Self> {
        let session_id = msg.get_avp(263).and_then(|a| a.as_string())?;
        let origin_host = msg
            .get_avp(264)
            .and_then(|a| a.as_string())
            .unwrap_or_default();
        let origin_realm = msg
            .get_avp(296)
            .and_then(|a| a.as_string())
            .unwrap_or_default();
        let destination_host = msg
            .get_avp(293)
            .and_then(|a| a.as_string())
            .unwrap_or_default();
        let destination_realm = msg
            .get_avp(283)
            .and_then(|a| a.as_string())
            .unwrap_or_default();

        let mut rules_to_install = Vec::new();
        let mut rules_to_remove = Vec::new();
        let mut event_triggers = Vec::new();

        for avp in &msg.avps {
            if avp.code == AVP_CHARGING_RULE_INSTALL {
                let inner = DiameterAvp::parse_all(&avp.data);
                for sub in inner {
                    if sub.code == AVP_CHARGING_RULE_DEFINITION {
                        if let Some(r) = PccRule::from_grouped_avp(&sub) {
                            rules_to_install.push(r);
                        }
                    }
                }
            } else if avp.code == AVP_CHARGING_RULE_REMOVE {
                let inner = DiameterAvp::parse_all(&avp.data);
                for sub in inner {
                    if sub.code == AVP_CHARGING_RULE_NAME {
                        rules_to_remove.push(String::from_utf8_lossy(&sub.data).to_string());
                    }
                }
            } else if avp.code == AVP_EVENT_TRIGGER {
                if let Some(trig) = avp.as_u32() {
                    event_triggers.push(trig);
                }
            }
        }

        Some(GxReAuthRequest {
            session_id,
            origin_host,
            origin_realm,
            destination_host,
            destination_realm,
            rules_to_install,
            rules_to_remove,
            event_triggers,
        })
    }
}

/// Diameter Gx Re-Auth-Answer (RAA) sent by PCEF to PCRF (3GPP TS 29.212).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GxReAuthAnswer {
    pub session_id: String,
    pub result_code: u32,
    pub origin_host: String,
    pub origin_realm: String,
}

impl GxReAuthAnswer {
    pub fn to_diameter_message(&self, hop_by_hop: u32, end_to_end: u32) -> DiameterMessage {
        let mut msg = DiameterMessage::new_answer(
            DIAMETER_CMD_RE_AUTH,
            DIAMETER_APPLICATION_GX,
            hop_by_hop,
            end_to_end,
        );
        msg.add_avp(DiameterAvp::new_utf8(263, &self.session_id));
        msg.add_avp(DiameterAvp::new_u32(268, self.result_code));
        msg.add_avp(DiameterAvp::new_utf8(264, &self.origin_host));
        msg.add_avp(DiameterAvp::new_utf8(296, &self.origin_realm));
        msg
    }

    pub fn from_diameter_message(msg: &DiameterMessage) -> Option<Self> {
        let session_id = msg.get_avp(263).and_then(|a| a.as_string())?;
        let result_code = msg
            .get_avp(268)
            .and_then(|a| a.as_u32())
            .unwrap_or(DIAMETER_SUCCESS);
        let origin_host = msg
            .get_avp(264)
            .and_then(|a| a.as_string())
            .unwrap_or_default();
        let origin_realm = msg
            .get_avp(296)
            .and_then(|a| a.as_string())
            .unwrap_or_default();

        Some(GxReAuthAnswer {
            session_id,
            result_code,
            origin_host,
            origin_realm,
        })
    }
}

/// State of an active Gx session tracked by PCRF.
#[derive(Debug, Clone)]
pub struct GxSessionState {
    pub subscriber_id: String,
    pub ip_can_type: IpCanType,
    pub active_rules: Vec<PccRule>,
}

/// PCRF Policy and Charging Rules Function Gx Server Engine.
#[derive(Debug, Clone)]
pub struct PcrfGxEngine {
    pub pcrf_host: String,
    pub pcrf_realm: String,
    pub sessions: HashMap<String, GxSessionState>,
}

impl PcrfGxEngine {
    pub fn new(pcrf_host: &str, pcrf_realm: &str) -> Self {
        PcrfGxEngine {
            pcrf_host: pcrf_host.to_string(),
            pcrf_realm: pcrf_realm.to_string(),
            sessions: HashMap::new(),
        }
    }

    /// Handles an incoming CCR Initial from PCEF, registering the session and provisioning default rules.
    pub fn handle_ccr_initial(
        &mut self,
        ccr: &GxCreditControlRequest,
    ) -> (DiameterMessage, Vec<PccRule>) {
        let mut default_rules = Vec::new();
        let mut r_default = PccRule::new("rule-default-internet", 9, 20_000_000, 100_000_000);
        r_default
            .flow_descriptions
            .push("permit out ip from any to any".to_string());
        default_rules.push(r_default);

        if ccr.ip_can_type == IpCanType::ThreeGpp5Gs || ccr.ip_can_type == IpCanType::ThreeGppEps {
            let mut r_ims = PccRule::new("rule-ims-signalling", 5, 512_000, 512_000);
            r_ims
                .flow_descriptions
                .push("permit out udp from any to 10.0.0.1 5060".to_string());
            default_rules.push(r_ims);
        }

        self.sessions.insert(
            ccr.session_id.clone(),
            GxSessionState {
                subscriber_id: ccr.subscription_id.clone(),
                ip_can_type: ccr.ip_can_type,
                active_rules: default_rules.clone(),
            },
        );

        let mut cca = DiameterMessage::new_answer(DIAMETER_CMD_CC, DIAMETER_APPLICATION_GX, 1, 1);
        cca.add_avp(DiameterAvp::new_utf8(263, &ccr.session_id));
        cca.add_avp(DiameterAvp::new_u32(268, DIAMETER_SUCCESS));
        cca.add_avp(DiameterAvp::new_u32(
            416,
            CcRequestType::InitialRequest as u32,
        ));
        cca.add_avp(DiameterAvp::new_u32(415, ccr.cc_request_number));

        for rule in &default_rules {
            let def_avp = rule.to_grouped_avp();
            cca.add_avp(DiameterAvp::new_vendor(
                AVP_CHARGING_RULE_INSTALL,
                DIAMETER_FLAG_MANDATORY | DIAMETER_FLAG_VENDOR_SPECIFIC,
                VENDOR_3GPP,
                &def_avp.serialize(),
            ));
        }

        (cca, default_rules)
    }

    /// Asynchronously pushes a RAR to install or remove rules on the PCEF.
    pub fn push_rar(
        &mut self,
        session_id: &str,
        pcef_host: &str,
        pcef_realm: &str,
        install: Vec<PccRule>,
        remove: Vec<String>,
    ) -> Option<GxReAuthRequest> {
        let session = self.sessions.get_mut(session_id)?;

        // Update local PCRF state
        for r_name in &remove {
            session.active_rules.retain(|r| &r.rule_name != r_name);
        }
        for rule in &install {
            session
                .active_rules
                .retain(|r| r.rule_name != rule.rule_name);
            session.active_rules.push(rule.clone());
        }

        Some(GxReAuthRequest {
            session_id: session_id.to_string(),
            origin_host: self.pcrf_host.clone(),
            origin_realm: self.pcrf_realm.clone(),
            destination_host: pcef_host.to_string(),
            destination_realm: pcef_realm.to_string(),
            rules_to_install: install,
            rules_to_remove: remove,
            event_triggers: Vec::new(),
        })
    }

    /// Terminates an active Gx session.
    pub fn terminate_session(&mut self, session_id: &str) -> bool {
        self.sessions.remove(session_id).is_some()
    }

    /// Returns the number of active Gx sessions.
    pub fn active_session_count(&self) -> usize {
        self.sessions.len()
    }
}

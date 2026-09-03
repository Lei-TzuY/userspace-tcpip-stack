//! 3GPP TS 29.512 / TS 29.514 5G Policy Control Function (PCF) Engine.
//!
//! Implements 5G Core Policy and Charging Control:
//! - Npcf_SMPolicyControl Service (TS 29.512):
//!   - Session Management Policy Association (Create, Update, Delete)
//!   - Dynamic PCC (Policy and Charging Control) Rule Engine
//!   - Multi-flow packet classification and 5QI / QFI / Session-AMBR authorization
//!   - GBR / Non-GBR QoS enforcement and Gate Status (Open/Closed)
//! - Npcf_PolicyAuthorization Service (TS 29.514):
//!   - Application Function (AF) Session Context authorization
//!   - On-demand dynamic dedicated QoS bearer and latency reservation (e.g. IMS Voice, XR/Cloud Gaming)

use std::collections::HashMap;

use crate::ipv4::Ipv4Address;
use crate::ngap_5g::Snssai;

// ---------------------------------------------------------------------------
// Packet Filters & Flow Descriptions (TS 29.512 Section 5.6.2)
// ---------------------------------------------------------------------------

/// Direction of traffic flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowDirection {
    Downlink,
    Uplink,
    Bidirectional,
}

/// 5G Packet Filter for IP traffic matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketFilter {
    pub filter_id: String,
    pub direction: FlowDirection,
    pub protocol: Option<u8>, // e.g. 6 = TCP, 17 = UDP
    pub source_ip: Option<Ipv4Address>,
    pub source_port: Option<u16>,
    pub dest_ip: Option<Ipv4Address>,
    pub dest_port: Option<u16>,
}

impl PacketFilter {
    /// Check if an IP packet tuple matches this filter.
    pub fn matches(
        &self,
        is_downlink: bool,
        src_ip: &Ipv4Address,
        dst_ip: &Ipv4Address,
        protocol: u8,
        src_port: u16,
        dst_port: u16,
    ) -> bool {
        // Direction check
        match self.direction {
            FlowDirection::Downlink if !is_downlink => return false,
            FlowDirection::Uplink if is_downlink => return false,
            _ => {}
        }

        // Protocol check
        if let Some(p) = self.protocol {
            if p != protocol {
                return false;
            }
        }

        // IP checks
        if let Some(ref sip) = self.source_ip {
            if sip != src_ip {
                return false;
            }
        }
        if let Some(ref dip) = self.dest_ip {
            if dip != dst_ip {
                return false;
            }
        }

        // Port checks
        if let Some(sport) = self.source_port {
            if sport != src_port {
                return false;
            }
        }
        if let Some(dport) = self.dest_port {
            if dport != dst_port {
                return false;
            }
        }

        true
    }
}

// ---------------------------------------------------------------------------
// PCC Rules (Policy and Charging Control - TS 29.512 Section 4.2.6)
// ---------------------------------------------------------------------------

/// Policy and Charging Control (PCC) Rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PccRule {
    pub rule_id: String,
    pub precedence: u32, // Lower number = higher priority
    pub packet_filters: Vec<PacketFilter>,
    pub five_qi: u8,
    pub qfi: u8,
    pub gbr_dl_kbps: Option<u32>,
    pub gbr_ul_kbps: Option<u32>,
    pub mbr_dl_kbps: Option<u32>,
    pub mbr_ul_kbps: Option<u32>,
    pub rating_group: u32,
    pub gate_status_open: bool, // true = allow/open, false = mute/drop
}

impl PccRule {
    /// Create a default best-effort (5QI=9) Non-GBR PCC Rule matching all traffic.
    pub fn default_best_effort(rule_id: &str) -> Self {
        let match_all = PacketFilter {
            filter_id: format!("{}-all", rule_id),
            direction: FlowDirection::Bidirectional,
            protocol: None,
            source_ip: None,
            source_port: None,
            dest_ip: None,
            dest_port: None,
        };

        PccRule {
            rule_id: rule_id.to_string(),
            precedence: 1000, // Lowest priority (default fallback)
            packet_filters: vec![match_all],
            five_qi: 9,
            qfi: 9,
            gbr_dl_kbps: None,
            gbr_ul_kbps: None,
            mbr_dl_kbps: Some(100_000),
            mbr_ul_kbps: Some(50_000),
            rating_group: 100,
            gate_status_open: true,
        }
    }
}

/// 5G PCC Rule alias for disambiguation with 4G Gx PCC Rule.
pub type PccRule5G = PccRule;

// ---------------------------------------------------------------------------
// Npcf_SMPolicyControl Service Operations (TS 29.512 Section 5.2)
// ---------------------------------------------------------------------------

/// Policy event triggers reported from SMF to PCF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyEventTrigger {
    PlmnChange,
    UserLocationChange,
    UeIpAllocationChange,
    UsageReportThresholdReached,
}

/// Request for Npcf_SMPolicyControl_Create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateSmPolicyRequest {
    pub supi: String,
    pub pdu_session_id: u8,
    pub dnn: String,
    pub s_nssai: Snssai,
    pub ue_ipv4: Ipv4Address,
}

/// Response for Npcf_SMPolicyControl_Create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateSmPolicyResponse {
    pub policy_ref: String,
    pub session_ambr_dl_kbps: u32,
    pub session_ambr_ul_kbps: u32,
    pub initial_pcc_rules: Vec<PccRule>,
    pub subscribed_events: Vec<PolicyEventTrigger>,
}

/// Request for Npcf_SMPolicyControl_Update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateSmPolicyRequest {
    pub policy_ref: String,
    pub triggers: Vec<PolicyEventTrigger>,
    pub consumed_dl_bytes: Option<u64>,
}

/// Response for Npcf_SMPolicyControl_Update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateSmPolicyResponse {
    pub modified_pcc_rules: Vec<PccRule>,
    pub removed_pcc_rule_ids: Vec<String>,
}

// ---------------------------------------------------------------------------
// Npcf_PolicyAuthorization Service Operations (TS 29.514 Section 5.2)
// ---------------------------------------------------------------------------

/// Media type requested by external Application Function (AF).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AfMediaType {
    Audio,
    Video,
    Gaming,
    MissionCritical,
}

/// Request for Npcf_PolicyAuthorization_Create (AF -> PCF).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppSessionContextRequest {
    pub app_session_id: String,
    pub supi: String,
    pub af_id: String,
    pub media_type: AfMediaType,
    pub requested_bandwidth_kbps: u32,
    pub flow_descriptions: Vec<PacketFilter>,
}

/// Response for Npcf_PolicyAuthorization_Create (PCF -> AF).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppSessionContextResponse {
    pub authorized: bool,
    pub assigned_5qi: u8,
    pub generated_pcc_rule: Option<PccRule>,
}

// ---------------------------------------------------------------------------
// PCF Policy Context & Engine
// ---------------------------------------------------------------------------

/// Active SM Policy association maintained by PCF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmPolicyAssociation {
    pub policy_ref: String,
    pub supi: String,
    pub pdu_session_id: u8,
    pub dnn: String,
    pub s_nssai: Snssai,
    pub ue_ipv4: Ipv4Address,
    pub session_ambr_dl_kbps: u32,
    pub session_ambr_ul_kbps: u32,
    pub pcc_rules: Vec<PccRule>,
    pub next_rule_id: u32,
}

/// 5G Policy Control Function (PCF) Engine.
pub struct PcfEngine {
    pub pcf_instance_id: String,
    pub next_policy_id: u32,
    pub policy_associations: HashMap<String, SmPolicyAssociation>, // policy_ref -> association
}

impl PcfEngine {
    /// Create a new PCF engine instance.
    pub fn new(pcf_instance_id: &str) -> Self {
        PcfEngine {
            pcf_instance_id: pcf_instance_id.to_string(),
            next_policy_id: 1001,
            policy_associations: HashMap::new(),
        }
    }

    /// Npcf_SMPolicyControl_Create: Establish policy association for a new PDU Session.
    pub fn handle_create_sm_policy(
        &mut self,
        req: &CreateSmPolicyRequest,
    ) -> Result<CreateSmPolicyResponse, &'static str> {
        let policy_ref = format!("urn:sm-policy:{}", self.next_policy_id);
        self.next_policy_id += 1;

        // Default slice/DNN AMBR limits
        let ambr_dl = 200_000;
        let ambr_ul = 100_000;

        // Create default best-effort PCC rule (Precedence 1000)
        let default_rule = PccRule::default_best_effort("pcc-default-001");

        let assoc = SmPolicyAssociation {
            policy_ref: policy_ref.clone(),
            supi: req.supi.clone(),
            pdu_session_id: req.pdu_session_id,
            dnn: req.dnn.clone(),
            s_nssai: req.s_nssai.clone(),
            ue_ipv4: req.ue_ipv4,
            session_ambr_dl_kbps: ambr_dl,
            session_ambr_ul_kbps: ambr_ul,
            pcc_rules: vec![default_rule.clone()],
            next_rule_id: 2,
        };
        self.policy_associations.insert(policy_ref.clone(), assoc);

        Ok(CreateSmPolicyResponse {
            policy_ref,
            session_ambr_dl_kbps: ambr_dl,
            session_ambr_ul_kbps: ambr_ul,
            initial_pcc_rules: vec![default_rule],
            subscribed_events: vec![
                PolicyEventTrigger::PlmnChange,
                PolicyEventTrigger::UserLocationChange,
                PolicyEventTrigger::UsageReportThresholdReached,
            ],
        })
    }

    /// Npcf_SMPolicyControl_Update: Update policies upon event triggers or quota consumption.
    pub fn handle_update_sm_policy(
        &mut self,
        req: &UpdateSmPolicyRequest,
    ) -> Result<UpdateSmPolicyResponse, &'static str> {
        let assoc = self
            .policy_associations
            .get_mut(&req.policy_ref)
            .ok_or("Policy association not found")?;

        let mut modified = Vec::new();

        // If usage threshold reached (> 100 MB), throttle best-effort rule gate
        if req
            .triggers
            .contains(&PolicyEventTrigger::UsageReportThresholdReached)
        {
            for rule in &mut assoc.pcc_rules {
                if rule.five_qi == 9 {
                    rule.mbr_dl_kbps = Some(1_000); // Throttled to 1 Mbps
                    rule.mbr_ul_kbps = Some(500);
                    modified.push(rule.clone());
                }
            }
        }

        Ok(UpdateSmPolicyResponse {
            modified_pcc_rules: modified,
            removed_pcc_rule_ids: Vec::new(),
        })
    }

    /// Npcf_SMPolicyControl_Delete: Delete policy association upon PDU session termination.
    pub fn handle_delete_sm_policy(&mut self, policy_ref: &str) -> bool {
        self.policy_associations.remove(policy_ref).is_some()
    }

    /// Npcf_PolicyAuthorization_Create: AF dynamic QoS reservation.
    /// Dynamically injects a high-priority dedicated GBR PCC rule into the subscriber's PDU session.
    pub fn handle_af_session_authorization(
        &mut self,
        req: &AppSessionContextRequest,
    ) -> Result<AppSessionContextResponse, &'static str> {
        // Locate active policy association for this subscriber
        let assoc = self
            .policy_associations
            .values_mut()
            .find(|a| a.supi == req.supi)
            .ok_or("Active PDU session policy association not found for subscriber")?;

        let (five_qi, qfi, precedence) = match req.media_type {
            AfMediaType::Audio => (1, 1, 10), // 5QI=1 (GBR Conversational Voice)
            AfMediaType::Video => (2, 2, 20), // 5QI=2 (GBR Conversational Video)
            AfMediaType::Gaming => (3, 3, 30), // 5QI=3 (GBR Real Time Gaming)
            AfMediaType::MissionCritical => (65, 4, 5), // 5QI=65 (Mission Critical User Plane)
        };

        let rule_id = format!("pcc-dyn-{}", assoc.next_rule_id);
        assoc.next_rule_id += 1;

        let dedicated_rule = PccRule {
            rule_id: rule_id.clone(),
            precedence,
            packet_filters: req.flow_descriptions.clone(),
            five_qi,
            qfi,
            gbr_dl_kbps: Some(req.requested_bandwidth_kbps),
            gbr_ul_kbps: Some(req.requested_bandwidth_kbps / 2),
            mbr_dl_kbps: Some(req.requested_bandwidth_kbps * 2),
            mbr_ul_kbps: Some(req.requested_bandwidth_kbps),
            rating_group: 200,
            gate_status_open: true,
        };

        assoc.pcc_rules.push(dedicated_rule.clone());

        Ok(AppSessionContextResponse {
            authorized: true,
            assigned_5qi: five_qi,
            generated_pcc_rule: Some(dedicated_rule),
        })
    }

    /// Classify an IP packet across active PCC rules for a PDU session.
    /// Returns the matched rule with highest priority (lowest precedence value).
    pub fn classify_packet(
        &self,
        policy_ref: &str,
        is_downlink: bool,
        src_ip: &Ipv4Address,
        dst_ip: &Ipv4Address,
        protocol: u8,
        src_port: u16,
        dst_port: u16,
    ) -> Option<&PccRule> {
        let assoc = self.policy_associations.get(policy_ref)?;

        let mut sorted_rules: Vec<&PccRule> = assoc.pcc_rules.iter().collect();
        sorted_rules.sort_by_key(|r| r.precedence);

        for rule in sorted_rules {
            for filter in &rule.packet_filters {
                if filter.matches(is_downlink, src_ip, dst_ip, protocol, src_port, dst_port) {
                    return Some(rule);
                }
            }
        }

        None
    }
}

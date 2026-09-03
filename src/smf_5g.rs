//! 3GPP TS 29.502 / TS 23.502 5G Session Management Function (SMF) Engine.
//!
//! Implements the 5G Core Session Management Function (SMF) control plane orchestration:
//! - Nsmf_PDUSession Service-Based Interface (Create, Update, Release SM Context)
//! - IP Address Management (IPAM) pool allocator for UE user-plane IPv4 assignment
//! - N4 PFCP Session programming on UPF (PDR & FAR installation for UL/DL GTP-U forwarding)
//! - Coordination with 5GSM NAS signaling (`nas_5g`) and N2 NGAP bearer setup (`ngap_5g`)
//! - Handover execution and tunnel re-anchoring across gNodeBs

use std::collections::HashMap;

use crate::ipv4::Ipv4Address;
use crate::nas_5g::{Nas5GsmMessage, NasPdu, PduSessionEstablishmentAccept};
use crate::ngap_5g::{PduSessionResourceSetupRequest, Snssai};
use crate::pfcp_5g::{
    ForwardingActionRule, PFCP_APPLY_ACTION_FORWARD, PFCP_SRC_INTERFACE_ACCESS,
    PFCP_SRC_INTERFACE_CORE, PacketDetectionRule, PfcpNode, PfcpSession,
};

// ---------------------------------------------------------------------------
// SM Context States & Identifiers (TS 23.502 Section 4.3.2)
// ---------------------------------------------------------------------------

/// Operating state of an active 5G PDU Session on the SMF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmContextState {
    /// Initial request received; IP and UPF UL tunnel allocated; awaiting gNB DL tunnel.
    ActivePending,
    /// Fully established bidirectional user plane (UL UPF TEID <-> DL gNB TEID).
    Active,
    /// Handover or QoS update in progress.
    Modifying,
    /// Session teardown in progress.
    Releasing,
}

/// Update reason for Nsmf_PDUSession_UpdateSMContext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmContextUpdateType {
    /// Initial gNodeB downlink tunnel binding.
    InitialDlTunnelSetup,
    /// Xn or N2 Handover to a target gNodeB (DL tunnel switch).
    HandoverExecution,
    /// QoS Flow modification.
    QosModification,
}

// ---------------------------------------------------------------------------
// IP Address Management (IPAM) Pool Allocator
// ---------------------------------------------------------------------------

/// Simple userspace IPv4 Pool Allocator for 5G PDU Sessions.
#[derive(Debug, Clone)]
pub struct IpamPool {
    pub network_base: [u8; 4],
    pub next_host: u8,
    pub max_host: u8,
    pub allocated_ips: HashMap<Ipv4Address, u8>, // IP -> PDU session ID
}

impl IpamPool {
    /// Create a new IPAM pool, e.g. `10.45.0.0/24` from host `.2` to `.254`.
    pub fn new(net_prefix: [u8; 3], start_host: u8, max_host: u8) -> Self {
        IpamPool {
            network_base: [net_prefix[0], net_prefix[1], net_prefix[2], 0],
            next_host: start_host,
            max_host,
            allocated_ips: HashMap::new(),
        }
    }

    /// Allocate the next available IPv4 address from the pool.
    pub fn allocate_ip(&mut self, session_id: u8) -> Option<Ipv4Address> {
        if self.next_host > self.max_host {
            return None;
        }
        let ip = Ipv4Address::new(
            self.network_base[0],
            self.network_base[1],
            self.network_base[2],
            self.next_host,
        );
        self.next_host += 1;
        self.allocated_ips.insert(ip, session_id);
        Some(ip)
    }

    /// Release an allocated IPv4 address back to the pool.
    pub fn release_ip(&mut self, ip: &Ipv4Address) -> bool {
        self.allocated_ips.remove(ip).is_some()
    }
}

// ---------------------------------------------------------------------------
// 5G QoS Profile (TS 23.501 Section 5.7)
// ---------------------------------------------------------------------------

/// 5G QoS Profile associated with an established PDU Session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmfQosProfile {
    pub five_qi: u8, // e.g. 9 for eMBB Default
    pub qfi: u8,     // 1..64
    pub session_ambr_dl_kbps: u32,
    pub session_ambr_ul_kbps: u32,
    pub priority_level: u8,
}

impl Default for SmfQosProfile {
    fn default() -> Self {
        SmfQosProfile {
            five_qi: 9,
            qfi: 9,
            session_ambr_dl_kbps: 100_000,
            session_ambr_ul_kbps: 50_000,
            priority_level: 1,
        }
    }
}

// ---------------------------------------------------------------------------
// Nsmf_PDUSession Service Operations (TS 29.502 Section 5.2)
// ---------------------------------------------------------------------------

/// Request for Nsmf_PDUSession_CreateSMContext (AMF -> SMF).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateSmContextRequest {
    pub supi: String,
    pub pdu_session_id: u8,
    pub dnn: String,
    pub s_nssai: Snssai,
    pub amf_id: String,
    pub user_location_tai: u32,
    pub n1_sm_container: Vec<u8>, // Raw 5GSM PduSessionEstablishmentRequest
}

/// Response for Nsmf_PDUSession_CreateSMContext (SMF -> AMF).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateSmContextResponse {
    pub sm_context_ref: String,
    pub allocated_ipv4: Ipv4Address,
    pub upf_n3_transport_ip: Ipv4Address,
    pub upf_n3_ul_teid: u32,
    pub qfi: u8,
    pub n2_sm_info: PduSessionResourceSetupRequest,
    pub n1_sm_container: Vec<u8>, // Raw 5GSM PduSessionEstablishmentAccept
}

/// Request for Nsmf_PDUSession_UpdateSMContext (AMF -> SMF).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateSmContextRequest {
    pub sm_context_ref: String,
    pub update_type: SmContextUpdateType,
    pub an_tunnel_ip: Ipv4Address, // gNodeB downlink transport IP
    pub an_tunnel_teid: u32,       // gNodeB downlink GTP-U TEID
}

/// Response for Nsmf_PDUSession_UpdateSMContext (SMF -> AMF).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateSmContextResponse {
    pub success: bool,
    pub current_state: SmContextState,
}

/// Request for Nsmf_PDUSession_ReleaseSMContext (AMF -> SMF).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseSmContextRequest {
    pub sm_context_ref: String,
    pub cause: Option<String>,
}

/// Response for Nsmf_PDUSession_ReleaseSMContext (SMF -> AMF).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseSmContextResponse {
    pub success: bool,
    pub released_ipv4: Option<Ipv4Address>,
}

// ---------------------------------------------------------------------------
// SMF UE Session Context
// ---------------------------------------------------------------------------

/// Managed PDU Session Context inside the SMF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmfSessionContext {
    pub sm_context_ref: String,
    pub supi: String,
    pub pdu_session_id: u8,
    pub dnn: String,
    pub s_nssai: Snssai,
    pub state: SmContextState,
    pub allocated_ip: Ipv4Address,
    pub upf_n3_ul_teid: u32,
    pub gnb_n3_dl_ip: Option<Ipv4Address>,
    pub gnb_n3_dl_teid: Option<u32>,
    pub qos_profile: SmfQosProfile,
    pub pfcp_session_seid: u64,
}

// ---------------------------------------------------------------------------
// Top-Level SMF Protocol Engine
// ---------------------------------------------------------------------------

/// 5G Session Management Function (SMF) Engine.
pub struct SmfEngine {
    pub smf_instance_id: String,
    pub ipam: IpamPool,
    pub upf_transport_ip: Ipv4Address,
    pub next_upf_teid: u32,
    pub next_sm_context_id: u32,
    pub pfcp_node: PfcpNode,
    pub active_sessions: HashMap<String, SmfSessionContext>, // Keyed by sm_context_ref
}

impl SmfEngine {
    /// Create a new SMF engine instance.
    pub fn new(smf_instance_id: &str, upf_transport_ip: Ipv4Address, ipam_prefix: [u8; 3]) -> Self {
        let mut pfcp = PfcpNode::default();
        pfcp.node_id = "upf-edge-001".to_string();
        pfcp.is_associated = true;

        SmfEngine {
            smf_instance_id: smf_instance_id.to_string(),
            ipam: IpamPool::new(ipam_prefix, 2, 254),
            upf_transport_ip,
            next_upf_teid: 0x1000_0001,
            next_sm_context_id: 1001,
            pfcp_node: pfcp,
            active_sessions: HashMap::new(),
        }
    }

    /// Process Nsmf_PDUSession_CreateSMContext from AMF.
    pub fn handle_create_sm_context(
        &mut self,
        req: &CreateSmContextRequest,
    ) -> Result<CreateSmContextResponse, &'static str> {
        // 1. Parse encapsulated 5GSM PduSessionEstablishmentRequest
        let inner_pdu =
            NasPdu::from_bytes(&req.n1_sm_container).ok_or("Failed to decode inner 5GSM PDU")?;
        let gsm_req = match inner_pdu.gsm_message {
            Some(Nas5GsmMessage::EstablishmentRequest(r)) => r,
            _ => return Err("Inner NAS message was not PduSessionEstablishmentRequest"),
        };

        // 2. Allocate IPv4 address for UE
        let ue_ip = self
            .ipam
            .allocate_ip(req.pdu_session_id)
            .ok_or("IPAM address exhaustion")?;

        // 3. Allocate UPF N3 Uplink TEID
        let upf_teid = self.next_upf_teid;
        self.next_upf_teid += 1;

        // 4. Create N4 PFCP Session on UPF
        let cp_seid = (req.pdu_session_id as u64) | 0x00C0_0000;
        let up_seid = (req.pdu_session_id as u64) | 0x00A0_0000;

        // Install Uplink PDR & FAR on UPF
        let ul_pdr = PacketDetectionRule {
            pdr_id: 1,
            precedence: 100,
            source_interface: PFCP_SRC_INTERFACE_ACCESS,
            teid: Some(upf_teid),
            ue_ip: None,
        };
        let ul_far = ForwardingActionRule {
            far_id: 1,
            apply_action: PFCP_APPLY_ACTION_FORWARD,
            destination_interface: PFCP_SRC_INTERFACE_CORE,
            outer_header_creation: None,
        };

        let pfcp_sess = PfcpSession {
            cp_seid,
            up_seid,
            pdrs: vec![ul_pdr],
            fars: vec![ul_far],
        };
        self.pfcp_node.sessions.insert(up_seid, pfcp_sess);

        // 5. Generate N1 SM Container: PduSessionEstablishmentAccept
        let qos = SmfQosProfile::default();
        let gsm_acc = PduSessionEstablishmentAccept {
            pdu_session_id: req.pdu_session_id,
            pti: gsm_req.pti,
            selected_pdu_session_type: gsm_req.pdu_session_type,
            selected_ssc_mode: gsm_req.ssc_mode,
            allocated_ipv4: Some(ue_ip),
            session_ambr_dl_kbps: qos.session_ambr_dl_kbps,
            session_ambr_ul_kbps: qos.session_ambr_ul_kbps,
            authorized_qfi: qos.qfi,
        };
        let plain_gsm = NasPdu::new_plain_gsm(Nas5GsmMessage::EstablishmentAccept(gsm_acc));
        let n1_sm_accept_bytes = plain_gsm.to_bytes();

        // 6. Generate N2 SM Info: PduSessionResourceSetupRequest for gNodeB
        let n2_setup = PduSessionResourceSetupRequest {
            amf_ue_ngap_id: 0x5001_0001,
            ran_ue_ngap_id: 0x2001,
            pdu_session_id: req.pdu_session_id,
            upf_transport_ip: self.upf_transport_ip,
            upf_gtpu_teid: upf_teid,
        };

        // 7. Store SM Context
        let sm_ref = format!("urn:sm-context:{}", self.next_sm_context_id);
        self.next_sm_context_id += 1;

        let ctx = SmfSessionContext {
            sm_context_ref: sm_ref.clone(),
            supi: req.supi.clone(),
            pdu_session_id: req.pdu_session_id,
            dnn: req.dnn.clone(),
            s_nssai: req.s_nssai.clone(),
            state: SmContextState::ActivePending,
            allocated_ip: ue_ip,
            upf_n3_ul_teid: upf_teid,
            gnb_n3_dl_ip: None,
            gnb_n3_dl_teid: None,
            qos_profile: qos.clone(),
            pfcp_session_seid: up_seid,
        };
        self.active_sessions.insert(sm_ref.clone(), ctx);

        Ok(CreateSmContextResponse {
            sm_context_ref: sm_ref,
            allocated_ipv4: ue_ip,
            upf_n3_transport_ip: self.upf_transport_ip,
            upf_n3_ul_teid: upf_teid,
            qfi: qos.qfi,
            n2_sm_info: n2_setup,
            n1_sm_container: n1_sm_accept_bytes,
        })
    }

    /// Process Nsmf_PDUSession_UpdateSMContext from AMF (binds gNodeB DL tunnel or handles handover).
    pub fn handle_update_sm_context(
        &mut self,
        req: &UpdateSmContextRequest,
    ) -> Result<UpdateSmContextResponse, &'static str> {
        let ctx = self
            .active_sessions
            .get_mut(&req.sm_context_ref)
            .ok_or("SM Context not found")?;

        ctx.gnb_n3_dl_ip = Some(req.an_tunnel_ip);
        ctx.gnb_n3_dl_teid = Some(req.an_tunnel_teid);

        // Update N4 PFCP Session on UPF: install/update Downlink PDR & FAR
        let up_seid = ctx.pfcp_session_seid;
        let pfcp_sess = self
            .pfcp_node
            .sessions
            .get_mut(&up_seid)
            .ok_or("PFCP Session missing on UPF")?;

        let dl_pdr = PacketDetectionRule {
            pdr_id: 2,
            precedence: 100,
            source_interface: PFCP_SRC_INTERFACE_CORE,
            teid: None,
            ue_ip: Some(ctx.allocated_ip),
        };
        let dl_far = ForwardingActionRule {
            far_id: 2,
            apply_action: PFCP_APPLY_ACTION_FORWARD,
            destination_interface: PFCP_SRC_INTERFACE_ACCESS,
            outer_header_creation: Some((req.an_tunnel_teid, req.an_tunnel_ip)),
        };

        // Remove old DL rules if present
        pfcp_sess.pdrs.retain(|p| p.pdr_id != 2);
        pfcp_sess.fars.retain(|f| f.far_id != 2);

        pfcp_sess.pdrs.push(dl_pdr);
        pfcp_sess.fars.push(dl_far);

        ctx.state = SmContextState::Active;

        Ok(UpdateSmContextResponse {
            success: true,
            current_state: SmContextState::Active,
        })
    }

    /// Process Nsmf_PDUSession_ReleaseSMContext from AMF.
    pub fn handle_release_sm_context(
        &mut self,
        req: &ReleaseSmContextRequest,
    ) -> Result<ReleaseSmContextResponse, &'static str> {
        let mut ctx = self
            .active_sessions
            .remove(&req.sm_context_ref)
            .ok_or("SM Context not found")?;

        ctx.state = SmContextState::Releasing;

        // 1. Delete N4 PFCP Session on UPF
        self.pfcp_node.sessions.remove(&ctx.pfcp_session_seid);

        // 2. Free IPv4 address back to IPAM pool
        let freed_ip = ctx.allocated_ip;
        self.ipam.release_ip(&freed_ip);

        Ok(ReleaseSmContextResponse {
            success: true,
            released_ipv4: Some(freed_ip),
        })
    }
}

//! 3GPP TS 38.463 E1 Application Protocol (E1AP) Control Plane Engine.
//!
//! Implements 5G gNodeB Centralized Unit Control Plane (gNB-CU-CP) <->
//! Centralized Unit User Plane (gNB-CU-UP) control plane signaling over SCTP port 38462,
//! including E1 Setup procedures and Bearer Context Management with F1-U and N3 tunnel bindings.

use std::collections::HashMap;

use crate::f1ap_5g::RlcMode;
use crate::ipv4::Ipv4Address;
use crate::ngap_5g::{PlmnId, Snssai};

/// Default SCTP port for 3GPP TS 38.463 E1AP.
pub const E1AP_SCTP_PORT: u16 = 38462;

/// Elementary Procedure Codes per 3GPP TS 38.463 Section 9.3.1.
pub const E1AP_PROC_GNB_CU_UP_E1_SETUP: u8 = 0;
pub const E1AP_PROC_BEARER_CONTEXT_SETUP: u8 = 2;
pub const E1AP_PROC_BEARER_CONTEXT_MODIFICATION: u8 = 3;
pub const E1AP_PROC_BEARER_CONTEXT_RELEASE: u8 = 4;

/// Role in the E1 interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum E1apRole {
    CuCp,
    CuUp,
}

/// E1 Interface Connection State.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum E1apState {
    Idle,
    SetupPending,
    Active,
}

/// E1 Setup Request (gNB-CU-UP -> gNB-CU-CP).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GnbCuUpE1SetupRequest {
    pub transaction_id: u8,
    pub gnb_cu_up_id: u64,
    pub gnb_cu_up_name: Option<String>,
    pub cn_support: bool, // true = 5GC, false = EPC
    pub supported_plmns: Vec<(PlmnId, Vec<Snssai>)>,
}

/// E1 Setup Response (gNB-CU-CP -> gNB-CU-UP).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GnbCuUpE1SetupResponse {
    pub transaction_id: u8,
    pub gnb_cu_cp_name: Option<String>,
}

/// E1 Setup Failure (gNB-CU-CP -> gNB-CU-UP).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GnbCuUpE1SetupFailure {
    pub transaction_id: u8,
    pub cause: &'static str,
}

/// DRB Setup Item (CP -> UP in BearerContextSetupRequest).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct E1apDrbSetupItem {
    pub drb_id: u8,
    pub qfi_list: Vec<u8>,
    pub pdcp_sn_size: u8, // 12 or 18 bit
    pub rlc_mode: RlcMode,
    pub du_f1u_dl_transport_ip: Ipv4Address,
    pub du_f1u_dl_gtp_teid: u32,
}

/// PDU Session Setup Item (CP -> UP in BearerContextSetupRequest).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct E1apPduSessionItem {
    pub pdu_session_id: u8,
    pub snssai: Snssai,
    pub drb_to_setup_list: Vec<E1apDrbSetupItem>,
}

/// DRB Setup Response Item (UP -> CP in BearerContextSetupResponse).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct E1apDrbSetupResponseItem {
    pub drb_id: u8,
    pub cu_up_f1u_dl_transport_ip: Ipv4Address,
    pub cu_up_f1u_dl_gtp_teid: u32,
    pub cu_up_ngu_ul_transport_ip: Ipv4Address,
    pub cu_up_ngu_ul_gtp_teid: u32,
}

/// PDU Session Setup Response Item (UP -> CP in BearerContextSetupResponse).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct E1apPduSessionResponseItem {
    pub pdu_session_id: u8,
    pub drb_setup_list: Vec<E1apDrbSetupResponseItem>,
}

/// Bearer Context Setup Request (gNB-CU-CP -> gNB-CU-UP).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BearerContextSetupRequest {
    pub gnb_cu_cp_ue_e1ap_id: u32,
    pub pdu_sessions: Vec<E1apPduSessionItem>,
}

/// Bearer Context Setup Response (gNB-CU-UP -> gNB-CU-CP).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BearerContextSetupResponse {
    pub gnb_cu_cp_ue_e1ap_id: u32,
    pub gnb_cu_up_ue_e1ap_id: u32,
    pub pdu_sessions: Vec<E1apPduSessionResponseItem>,
}

/// Bearer Context Release Command (gNB-CU-CP -> gNB-CU-UP).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BearerContextReleaseCommand {
    pub gnb_cu_cp_ue_e1ap_id: u32,
    pub gnb_cu_up_ue_e1ap_id: u32,
    pub cause: &'static str,
}

/// Active Bearer Context managed on CU-CP / CU-UP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct E1apBearerContext {
    pub gnb_cu_cp_ue_e1ap_id: u32,
    pub gnb_cu_up_ue_e1ap_id: u32,
    pub pdu_sessions: Vec<E1apPduSessionResponseItem>,
}

/// E1AP Control Plane Engine (gNB-CU-CP / gNB-CU-UP).
#[derive(Debug, Clone)]
pub struct E1apEngine {
    pub role: E1apRole,
    pub state: E1apState,
    pub gnb_id: u64,
    pub name: String,
    pub bearer_contexts: HashMap<u32, E1apBearerContext>,
    pub up_to_cp_id_map: HashMap<u32, u32>,
    next_tx_id: u8,
}

impl E1apEngine {
    pub fn new(role: E1apRole, gnb_id: u64, name: impl Into<String>) -> Self {
        Self {
            role,
            state: E1apState::Idle,
            gnb_id,
            name: name.into(),
            bearer_contexts: HashMap::new(),
            up_to_cp_id_map: HashMap::new(),
            next_tx_id: 1,
        }
    }

    /// Generates GnbCuUpE1SetupRequest (CU-UP -> CU-CP).
    pub fn initiate_e1_setup(
        &mut self,
        supported_plmns: Vec<(PlmnId, Vec<Snssai>)>,
    ) -> GnbCuUpE1SetupRequest {
        self.state = E1apState::SetupPending;
        let tx_id = self.next_tx_id;
        self.next_tx_id = self.next_tx_id.wrapping_add(1);

        GnbCuUpE1SetupRequest {
            transaction_id: tx_id,
            gnb_cu_up_id: self.gnb_id,
            gnb_cu_up_name: Some(self.name.clone()),
            cn_support: true,
            supported_plmns,
        }
    }

    /// Handles GnbCuUpE1SetupRequest on gNB-CU-CP.
    pub fn handle_e1_setup_request(
        &mut self,
        req: &GnbCuUpE1SetupRequest,
    ) -> Result<GnbCuUpE1SetupResponse, GnbCuUpE1SetupFailure> {
        if self.role != E1apRole::CuCp {
            return Err(GnbCuUpE1SetupFailure {
                transaction_id: req.transaction_id,
                cause: "Only CU-CP can process GnbCuUpE1SetupRequest",
            });
        }

        if req.supported_plmns.is_empty() {
            return Err(GnbCuUpE1SetupFailure {
                transaction_id: req.transaction_id,
                cause: "No supported PLMNs provided by CU-UP",
            });
        }

        self.state = E1apState::Active;

        Ok(GnbCuUpE1SetupResponse {
            transaction_id: req.transaction_id,
            gnb_cu_cp_name: Some(self.name.clone()),
        })
    }

    /// Handles GnbCuUpE1SetupResponse on gNB-CU-UP.
    pub fn handle_e1_setup_response(
        &mut self,
        _resp: &GnbCuUpE1SetupResponse,
    ) -> Result<(), &'static str> {
        if self.role != E1apRole::CuUp {
            return Err("Only CU-UP can process GnbCuUpE1SetupResponse");
        }
        if self.state != E1apState::SetupPending {
            return Err("Received GnbCuUpE1SetupResponse while not in SetupPending state");
        }

        self.state = E1apState::Active;
        Ok(())
    }

    /// Initiates Bearer Context Setup Request (CU-CP -> CU-UP).
    pub fn build_bearer_context_setup_request(
        &self,
        cp_ue_id: u32,
        pdu_sessions: Vec<E1apPduSessionItem>,
    ) -> Result<BearerContextSetupRequest, &'static str> {
        if self.state != E1apState::Active {
            return Err("Cannot setup Bearer Context: E1 interface is not active");
        }
        Ok(BearerContextSetupRequest {
            gnb_cu_cp_ue_e1ap_id: cp_ue_id,
            pdu_sessions,
        })
    }

    /// Handles Bearer Context Setup Request on CU-UP and allocates transport tunnel endpoints.
    pub fn handle_bearer_context_setup_request(
        &mut self,
        req: &BearerContextSetupRequest,
        cu_up_transport_ip: Ipv4Address,
        starting_teid: u32,
    ) -> Result<BearerContextSetupResponse, &'static str> {
        if self.role != E1apRole::CuUp {
            return Err("Only CU-UP can process BearerContextSetupRequest");
        }

        let up_ue_id = req.gnb_cu_cp_ue_e1ap_id + 500;
        let mut cur_teid = starting_teid;

        let mut pdu_resp_list = Vec::new();
        for sess in &req.pdu_sessions {
            let mut drb_resp_list = Vec::new();
            for drb in &sess.drb_to_setup_list {
                drb_resp_list.push(E1apDrbSetupResponseItem {
                    drb_id: drb.drb_id,
                    cu_up_f1u_dl_transport_ip: cu_up_transport_ip,
                    cu_up_f1u_dl_gtp_teid: cur_teid,
                    cu_up_ngu_ul_transport_ip: cu_up_transport_ip,
                    cu_up_ngu_ul_gtp_teid: cur_teid + 1,
                });
                cur_teid += 2;
            }
            pdu_resp_list.push(E1apPduSessionResponseItem {
                pdu_session_id: sess.pdu_session_id,
                drb_setup_list: drb_resp_list,
            });
        }

        let ctx = E1apBearerContext {
            gnb_cu_cp_ue_e1ap_id: req.gnb_cu_cp_ue_e1ap_id,
            gnb_cu_up_ue_e1ap_id: up_ue_id,
            pdu_sessions: pdu_resp_list.clone(),
        };

        self.bearer_contexts.insert(req.gnb_cu_cp_ue_e1ap_id, ctx);
        self.up_to_cp_id_map
            .insert(up_ue_id, req.gnb_cu_cp_ue_e1ap_id);

        Ok(BearerContextSetupResponse {
            gnb_cu_cp_ue_e1ap_id: req.gnb_cu_cp_ue_e1ap_id,
            gnb_cu_up_ue_e1ap_id: up_ue_id,
            pdu_sessions: pdu_resp_list,
        })
    }

    /// Handles Bearer Context Setup Response on CU-CP.
    pub fn handle_bearer_context_setup_response(
        &mut self,
        resp: &BearerContextSetupResponse,
    ) -> Result<(), &'static str> {
        if self.role != E1apRole::CuCp {
            return Err("Only CU-CP can process BearerContextSetupResponse");
        }

        let ctx = E1apBearerContext {
            gnb_cu_cp_ue_e1ap_id: resp.gnb_cu_cp_ue_e1ap_id,
            gnb_cu_up_ue_e1ap_id: resp.gnb_cu_up_ue_e1ap_id,
            pdu_sessions: resp.pdu_sessions.clone(),
        };

        self.bearer_contexts.insert(resp.gnb_cu_cp_ue_e1ap_id, ctx);
        self.up_to_cp_id_map
            .insert(resp.gnb_cu_up_ue_e1ap_id, resp.gnb_cu_cp_ue_e1ap_id);
        Ok(())
    }

    /// Finds a Bearer Context by CU-CP UE E1AP ID.
    pub fn lookup_by_cp_ue_id(&self, cp_ue_id: u32) -> Option<&E1apBearerContext> {
        self.bearer_contexts.get(&cp_ue_id)
    }

    /// Finds a Bearer Context by CU-UP UE E1AP ID.
    pub fn lookup_by_up_ue_id(&self, up_ue_id: u32) -> Option<&E1apBearerContext> {
        self.up_to_cp_id_map
            .get(&up_ue_id)
            .and_then(|cp_id| self.bearer_contexts.get(cp_id))
    }

    /// Releases a Bearer Context from both indexes.
    pub fn release_bearer_context(&mut self, cp_ue_id: u32) -> bool {
        if let Some(ctx) = self.bearer_contexts.remove(&cp_ue_id) {
            self.up_to_cp_id_map.remove(&ctx.gnb_cu_up_ue_e1ap_id);
            true
        } else {
            false
        }
    }
}

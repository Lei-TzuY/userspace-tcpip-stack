//! 3GPP TS 38.473 F1 Application Protocol (F1AP) Control Plane Engine.
//!
//! Implements 5G gNodeB Distributed Unit (gNB-DU) <-> Centralized Unit (gNB-CU)
//! control plane signaling over SCTP port 38472, including F1 Setup procedures,
//! UE Context Setup with F1-U GTP-U bearer binding, and RRC Message Transfer.

use std::collections::HashMap;

use crate::ipv4::Ipv4Address;
use crate::ngap_5g::{PlmnId, Snssai};

/// Default SCTP port for 3GPP TS 38.473 F1AP.
pub const F1AP_SCTP_PORT: u16 = 38472;

/// Elementary Procedure Codes per 3GPP TS 38.473 Section 9.3.1.
pub const F1AP_PROC_F1_SETUP: u8 = 0;
pub const F1AP_PROC_UE_CONTEXT_SETUP: u8 = 5;
pub const F1AP_PROC_UE_CONTEXT_RELEASE: u8 = 6;
pub const F1AP_PROC_INITIAL_UL_RRC: u8 = 19;
pub const F1AP_PROC_DL_RRC: u8 = 20;
pub const F1AP_PROC_UL_RRC: u8 = 21;

/// RLC Transmission Mode for Data Radio Bearers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RlcMode {
    RlcAm,
    RlcUmBidirectional,
    RlcUmUnidirectionalDl,
    RlcUmUnidirectionalUl,
}

/// Served Cell Information broadcast by gNB-DU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServedCellInfo {
    pub nr_cgi: u64,
    pub nr_pci: u16,
    pub tac: u32,
    pub plmn: PlmnId,
    pub arfcn_nr: u32,
    pub subcarrier_spacing_khz: u8,
    pub supported_slices: Vec<Snssai>,
}

/// Data Radio Bearer (DRB) to be setup (CU -> DU in UeContextSetupRequest).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrbSetupItem {
    pub drb_id: u8,
    pub cu_up_transport_ip: Ipv4Address,
    pub cu_up_gtp_teid: u32,
    pub qfi: u8,
    pub rlc_mode: RlcMode,
}

/// Data Radio Bearer (DRB) setup response (DU -> CU in UeContextSetupResponse).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrbSetupResponseItem {
    pub drb_id: u8,
    pub du_up_transport_ip: Ipv4Address,
    pub du_up_gtp_teid: u32,
}

/// F1 Setup Request (gNB-DU -> gNB-CU).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct F1SetupRequest {
    pub transaction_id: u8,
    pub gnb_du_id: u64,
    pub gnb_du_name: Option<String>,
    pub served_cells: Vec<ServedCellInfo>,
    pub rrc_version: u8,
}

/// F1 Setup Response (gNB-CU -> gNB-DU).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct F1SetupResponse {
    pub transaction_id: u8,
    pub gnb_cu_name: Option<String>,
    pub cells_to_activate: Vec<u64>,
}

/// F1 Setup Failure (gNB-CU -> gNB-DU).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct F1SetupFailure {
    pub transaction_id: u8,
    pub cause: &'static str,
}

/// Initial Uplink RRC Message Transfer (gNB-DU -> gNB-CU).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitialUlRrcMessageTransfer {
    pub gnb_du_ue_f1ap_id: u32,
    pub nr_cgi: u64,
    pub crnti: u16,
    pub rrc_container: Vec<u8>,
}

/// UE Context Setup Request (gNB-CU -> gNB-DU).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UeContextSetupRequest {
    pub gnb_cu_ue_f1ap_id: u32,
    pub gnb_du_ue_f1ap_id: Option<u32>,
    pub spcell_nr_cgi: u64,
    pub drb_to_be_setup_list: Vec<DrbSetupItem>,
    pub rrc_container: Option<Vec<u8>>,
}

/// UE Context Setup Response (gNB-DU -> gNB-CU).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UeContextSetupResponse {
    pub gnb_cu_ue_f1ap_id: u32,
    pub gnb_du_ue_f1ap_id: u32,
    pub drb_setup_list: Vec<DrbSetupResponseItem>,
    pub du_to_cu_rrc_information: Option<Vec<u8>>,
}

/// Downlink RRC Message Transfer (gNB-CU -> gNB-DU).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DlRrcMessageTransfer {
    pub gnb_cu_ue_f1ap_id: u32,
    pub gnb_du_ue_f1ap_id: u32,
    pub srb_id: u8,
    pub rrc_container: Vec<u8>,
}

/// Uplink RRC Message Transfer (gNB-DU -> gNB-CU).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UlRrcMessageTransfer {
    pub gnb_cu_ue_f1ap_id: u32,
    pub gnb_du_ue_f1ap_id: u32,
    pub srb_id: u8,
    pub rrc_container: Vec<u8>,
}

/// UE Context Release Command (gNB-CU -> gNB-DU).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UeContextReleaseCommand {
    pub gnb_cu_ue_f1ap_id: u32,
    pub gnb_du_ue_f1ap_id: u32,
    pub cause: &'static str,
}

/// F1AP Protocol Data Unit (PDU) Wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum F1apPdu {
    F1SetupRequest(F1SetupRequest),
    F1SetupResponse(F1SetupResponse),
    F1SetupFailure(F1SetupFailure),
    InitialUlRrc(InitialUlRrcMessageTransfer),
    UeContextSetupRequest(UeContextSetupRequest),
    UeContextSetupResponse(UeContextSetupResponse),
    DlRrcMessageTransfer(DlRrcMessageTransfer),
    UlRrcMessageTransfer(UlRrcMessageTransfer),
    UeContextReleaseCommand(UeContextReleaseCommand),
}

/// Role in the F1 interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum F1apRole {
    Cu,
    Du,
}

/// F1 Interface Connection State.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum F1apState {
    Idle,
    SetupPending,
    Active,
}

/// Active UE Context managed by F1AP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct F1apUeContext {
    pub gnb_cu_ue_f1ap_id: u32,
    pub gnb_du_ue_f1ap_id: u32,
    pub spcell_nr_cgi: u64,
    pub crnti: Option<u16>,
    pub drbs: Vec<DrbSetupResponseItem>,
}

/// F1AP Control Plane Engine (gNB-CU / gNB-DU).
#[derive(Debug, Clone)]
pub struct F1apEngine {
    pub role: F1apRole,
    pub state: F1apState,
    pub gnb_id: u64,
    pub name: String,
    pub served_cells: Vec<ServedCellInfo>,
    pub active_cells: Vec<u64>,
    pub ue_contexts: HashMap<u32, F1apUeContext>,
    pub du_to_cu_id_map: HashMap<u32, u32>,
    next_tx_id: u8,
}

impl F1apEngine {
    pub fn new(role: F1apRole, gnb_id: u64, name: impl Into<String>) -> Self {
        Self {
            role,
            state: F1apState::Idle,
            gnb_id,
            name: name.into(),
            served_cells: Vec::new(),
            active_cells: Vec::new(),
            ue_contexts: HashMap::new(),
            du_to_cu_id_map: HashMap::new(),
            next_tx_id: 1,
        }
    }

    /// Generates F1SetupRequest (DU -> CU).
    pub fn initiate_f1_setup(&mut self, served_cells: Vec<ServedCellInfo>) -> F1SetupRequest {
        self.state = F1apState::SetupPending;
        self.served_cells = served_cells.clone();
        let tx_id = self.next_tx_id;
        self.next_tx_id = self.next_tx_id.wrapping_add(1);

        F1SetupRequest {
            transaction_id: tx_id,
            gnb_du_id: self.gnb_id,
            gnb_du_name: Some(self.name.clone()),
            served_cells,
            rrc_version: 1,
        }
    }

    /// Handles F1SetupRequest on gNB-CU and generates F1SetupResponse.
    pub fn handle_f1_setup_request(
        &mut self,
        req: &F1SetupRequest,
    ) -> Result<F1SetupResponse, F1SetupFailure> {
        if self.role != F1apRole::Cu {
            return Err(F1SetupFailure {
                transaction_id: req.transaction_id,
                cause: "Only CU can process F1SetupRequest",
            });
        }

        if req.served_cells.is_empty() {
            return Err(F1SetupFailure {
                transaction_id: req.transaction_id,
                cause: "No served cells provided by DU",
            });
        }

        self.served_cells = req.served_cells.clone();
        self.active_cells = req.served_cells.iter().map(|c| c.nr_cgi).collect();
        self.state = F1apState::Active;

        Ok(F1SetupResponse {
            transaction_id: req.transaction_id,
            gnb_cu_name: Some(self.name.clone()),
            cells_to_activate: self.active_cells.clone(),
        })
    }

    /// Handles F1SetupResponse on gNB-DU.
    pub fn handle_f1_setup_response(&mut self, resp: &F1SetupResponse) -> Result<(), &'static str> {
        if self.role != F1apRole::Du {
            return Err("Only DU can process F1SetupResponse");
        }
        if self.state != F1apState::SetupPending {
            return Err("Received F1SetupResponse while not in SetupPending state");
        }

        self.active_cells = resp.cells_to_activate.clone();
        self.state = F1apState::Active;
        Ok(())
    }

    /// Initiates UE Context Setup (CU -> DU).
    pub fn build_ue_context_setup_request(
        &self,
        cu_ue_id: u32,
        du_ue_id: Option<u32>,
        spcell_nr_cgi: u64,
        drbs: Vec<DrbSetupItem>,
        rrc_container: Option<Vec<u8>>,
    ) -> Result<UeContextSetupRequest, &'static str> {
        if self.state != F1apState::Active {
            return Err("Cannot setup UE context: F1 interface is not active");
        }
        Ok(UeContextSetupRequest {
            gnb_cu_ue_f1ap_id: cu_ue_id,
            gnb_du_ue_f1ap_id: du_ue_id,
            spcell_nr_cgi,
            drb_to_be_setup_list: drbs,
            rrc_container,
        })
    }

    /// Handles UE Context Setup Request on DU and produces UE Context Setup Response.
    pub fn handle_ue_context_setup_request(
        &mut self,
        req: &UeContextSetupRequest,
        du_transport_ip: Ipv4Address,
        starting_teid: u32,
    ) -> Result<UeContextSetupResponse, &'static str> {
        if self.role != F1apRole::Du {
            return Err("Only DU can process UeContextSetupRequest");
        }

        let du_ue_id = req.gnb_du_ue_f1ap_id.unwrap_or(req.gnb_cu_ue_f1ap_id + 100);

        let mut drb_setup_list = Vec::new();
        for (i, drb) in req.drb_to_be_setup_list.iter().enumerate() {
            drb_setup_list.push(DrbSetupResponseItem {
                drb_id: drb.drb_id,
                du_up_transport_ip: du_transport_ip,
                du_up_gtp_teid: starting_teid + (i as u32),
            });
        }

        let ctx = F1apUeContext {
            gnb_cu_ue_f1ap_id: req.gnb_cu_ue_f1ap_id,
            gnb_du_ue_f1ap_id: du_ue_id,
            spcell_nr_cgi: req.spcell_nr_cgi,
            crnti: None,
            drbs: drb_setup_list.clone(),
        };

        self.ue_contexts.insert(req.gnb_cu_ue_f1ap_id, ctx);
        self.du_to_cu_id_map.insert(du_ue_id, req.gnb_cu_ue_f1ap_id);

        Ok(UeContextSetupResponse {
            gnb_cu_ue_f1ap_id: req.gnb_cu_ue_f1ap_id,
            gnb_du_ue_f1ap_id: du_ue_id,
            drb_setup_list,
            du_to_cu_rrc_information: Some(vec![0xAA, 0xBB]),
        })
    }

    /// Handles UE Context Setup Response on CU.
    pub fn handle_ue_context_setup_response(
        &mut self,
        resp: &UeContextSetupResponse,
        spcell_nr_cgi: u64,
    ) -> Result<(), &'static str> {
        if self.role != F1apRole::Cu {
            return Err("Only CU can process UeContextSetupResponse");
        }

        let ctx = F1apUeContext {
            gnb_cu_ue_f1ap_id: resp.gnb_cu_ue_f1ap_id,
            gnb_du_ue_f1ap_id: resp.gnb_du_ue_f1ap_id,
            spcell_nr_cgi,
            crnti: None,
            drbs: resp.drb_setup_list.clone(),
        };

        self.ue_contexts.insert(resp.gnb_cu_ue_f1ap_id, ctx);
        self.du_to_cu_id_map
            .insert(resp.gnb_du_ue_f1ap_id, resp.gnb_cu_ue_f1ap_id);
        Ok(())
    }

    /// Finds a UE context by CU UE F1AP ID.
    pub fn lookup_by_cu_ue_id(&self, cu_ue_id: u32) -> Option<&F1apUeContext> {
        self.ue_contexts.get(&cu_ue_id)
    }

    /// Finds a UE context by DU UE F1AP ID.
    pub fn lookup_by_du_ue_id(&self, du_ue_id: u32) -> Option<&F1apUeContext> {
        self.du_to_cu_id_map
            .get(&du_ue_id)
            .and_then(|cu_id| self.ue_contexts.get(cu_id))
    }

    /// Releases a UE context from both indexes.
    pub fn release_ue_context(&mut self, cu_ue_id: u32) -> bool {
        if let Some(ctx) = self.ue_contexts.remove(&cu_ue_id) {
            self.du_to_cu_id_map.remove(&ctx.gnb_du_ue_f1ap_id);
            true
        } else {
            false
        }
    }
}

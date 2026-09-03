//! 3GPP TS 38.423 5G Xn Application Protocol (XnAP) Control Plane Engine.
//!
//! Implements the 5G inter-gNodeB (gNB <-> gNB / ng-eNB) Xn-C control plane
//! signaling interface over SCTP port 38422 per 3GPP TS 38.420 and TS 38.423:
//! - Xn Setup & Management procedures (Section 8.4)
//! - Xn Handover Preparation, Execution & Context Transfer (Section 8.2)
//!   - HandoverRequest & HandoverRequestAcknowledge with Data Forwarding Tunnels
//!   - SN Status Transfer (PDCP DL/UL COUNT synchronization)
//!   - UE Context Release & Handover Cancel
//! - Dual Connectivity (MR-DC / NR-DC) Secondary gNodeB (S-gNB) Addition & Release
//! - Integration with RRC containers (TS 38.331) and Xn-U User Plane (TS 38.425)

use std::collections::HashMap;

use crate::ipv4::Ipv4Address;
use crate::ngap_5g::{PlmnId, Snssai};

// ---------------------------------------------------------------------------
// Constants & Elementary Procedure Codes (TS 38.423 Section 9.3.1)
// ---------------------------------------------------------------------------

/// Standard SCTP port for 3GPP TS 38.423 XnAP control plane.
pub const XNAP_SCTP_PORT: u16 = 38422;

/// Elementary Procedure Codes.
pub const XNAP_PROC_HANDOVER_PREPARATION: u8 = 0;
pub const XNAP_PROC_SN_STATUS_TRANSFER: u8 = 1;
pub const XNAP_PROC_HANDOVER_CANCEL: u8 = 2;
pub const XNAP_PROC_RETRIEVE_UE_CONTEXT: u8 = 3;
pub const XNAP_PROC_XN_SETUP: u8 = 4;
pub const XNAP_PROC_RESET: u8 = 5;
pub const XNAP_PROC_XN_REMOVAL: u8 = 6;
pub const XNAP_PROC_UE_CONTEXT_RELEASE: u8 = 7;
pub const XNAP_PROC_SECONDARY_NODE_ADDITION: u8 = 8;
pub const XNAP_PROC_SECONDARY_NODE_RECONFIG_COMPLETE: u8 = 9;
pub const XNAP_PROC_SECONDARY_NODE_RELEASE: u8 = 11;

// ---------------------------------------------------------------------------
// Causes (TS 38.423 Section 9.2.3.1)
// ---------------------------------------------------------------------------

/// XnAP failure and event causes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XnCause {
    /// Radio Network causes.
    HandoverDesirableForRadioReason,
    TimeCriticalHandover,
    NoRadioResourcesAvailableInTargetCell,
    TargetCellNotAvailable,
    InvalidQosCombination,
    EncryptionOrIntegrityAlgorithmsNotSupported,
    /// Transport Layer causes.
    TransportResourceUnavailable,
    /// Protocol error causes.
    TransferSyntaxError,
    AbstractSyntaxError,
    MessageNotCompatibleWithReceiverState,
    /// Miscellaneous.
    ControlProcessingOverload,
    HardwareFailure,
    OamIntervention,
    Unspecified,
}

// ---------------------------------------------------------------------------
// Served Cell Information (TS 38.423 Section 9.2.2.1)
// ---------------------------------------------------------------------------

/// Served NR cell information exchanged during Xn Setup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XnServedCellInfo {
    pub nr_cgi: u64,
    pub nr_pci: u16,
    pub tac: u32,
    pub plmn: PlmnId,
    pub arfcn_nr: u32,
    pub supported_slices: Vec<Snssai>,
}

// ---------------------------------------------------------------------------
// Bearer & Forwarding Information (TS 38.423 Section 9.2.1)
// ---------------------------------------------------------------------------

/// Information for a DRB to be setup or transferred.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XnDrbItem {
    pub drb_id: u8,
    pub qfi_list: Vec<u8>,
    pub dl_forwarding_required: bool,
    pub ul_forwarding_required: bool,
}

/// PDU session resource to be setup in target gNB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PduSessionResourceToBeSetup {
    pub pdu_session_id: u8,
    pub s_nssai: Snssai,
    pub upf_transport_ip: Ipv4Address,
    pub upf_gtp_teid: u32,
    pub drb_to_setup_list: Vec<XnDrbItem>,
}

/// Direct data forwarding tunnel info for lossless handover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XnDataForwardingTunnel {
    pub drb_id: u8,
    pub dl_forwarding_ip: Ipv4Address,
    pub dl_forwarding_teid: u32,
    pub ul_forwarding_ip: Option<Ipv4Address>,
    pub ul_forwarding_teid: Option<u32>,
}

/// PDU session resource successfully admitted by target gNB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PduSessionResourceAdmittedItem {
    pub pdu_session_id: u8,
    pub target_transport_ip: Ipv4Address,
    pub target_gtp_teid: u32,
    pub admitted_drbs: Vec<u8>,
    pub forwarding_tunnels: Vec<XnDataForwardingTunnel>,
}

/// Sequence Number and COUNT status per DRB for lossless handover transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnStatusItem {
    pub drb_id: u8,
    pub dl_count: u32,                          // Next DL COUNT to assign
    pub ul_count: u32,                          // First missing UL COUNT
    pub receive_status_bitmap: Option<Vec<u8>>, // Lost UL packet gap bitmap
}

// ---------------------------------------------------------------------------
// XnAP Messages (TS 38.423 Section 9.1)
// ---------------------------------------------------------------------------

/// Xn Setup Request (gNB1 -> gNB2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XnSetupRequest {
    pub transaction_id: u8,
    pub global_gnb_id: u32,
    pub gnb_name: Option<String>,
    pub served_cells: Vec<XnServedCellInfo>,
    pub tai_support_list: Vec<u32>,
}

/// Xn Setup Response (gNB2 -> gNB1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XnSetupResponse {
    pub transaction_id: u8,
    pub global_gnb_id: u32,
    pub gnb_name: Option<String>,
    pub served_cells: Vec<XnServedCellInfo>,
}

/// Xn Setup Failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XnSetupFailure {
    pub transaction_id: u8,
    pub cause: XnCause,
}

/// Handover Request (Source gNB -> Target gNB).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoverRequest {
    pub source_ue_xnap_id: u32,
    pub cause: XnCause,
    pub target_cell_nr_cgi: u64,
    pub guami: u32,
    pub amf_ue_ngap_id: u64,
    pub ue_security_capabilities: u16,
    pub next_hop_chaining_count: u8,
    pub pdu_session_resources_to_setup: Vec<PduSessionResourceToBeSetup>,
    pub rrc_context: Vec<u8>, // Source gNB transparent container (RRC Reconfiguration)
}

/// Handover Request Acknowledge (Target gNB -> Source gNB).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoverRequestAcknowledge {
    pub source_ue_xnap_id: u32,
    pub target_ue_xnap_id: u32,
    pub pdu_session_resources_admitted: Vec<PduSessionResourceAdmittedItem>,
    pub target_to_source_transparent_container: Vec<u8>, // Handover Command / RRC Reconfig with Sync
}

/// Handover Preparation Failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoverPreparationFailure {
    pub source_ue_xnap_id: u32,
    pub cause: XnCause,
}

/// SN Status Transfer (Source gNB -> Target gNB).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnStatusTransfer {
    pub source_ue_xnap_id: u32,
    pub target_ue_xnap_id: u32,
    pub sn_status_list: Vec<SnStatusItem>,
}

/// UE Context Release (Target gNB -> Source gNB after successful handover execution).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UeContextRelease {
    pub source_ue_xnap_id: u32,
    pub target_ue_xnap_id: u32,
}

/// Handover Cancel (Source gNB -> Target gNB).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoverCancel {
    pub source_ue_xnap_id: u32,
    pub target_ue_xnap_id: Option<u32>,
    pub cause: XnCause,
}

/// Secondary gNodeB (S-gNB) Addition Request (M-gNB -> S-gNB for Dual Connectivity).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SgNbAdditionRequest {
    pub m_gnb_ue_xnap_id: u32,
    pub target_cell_nr_cgi: u64,
    pub drb_to_offload_list: Vec<XnDrbItem>,
}

/// Secondary gNodeB (S-gNB) Addition Request Acknowledge (S-gNB -> M-gNB).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SgNbAdditionRequestAcknowledge {
    pub m_gnb_ue_xnap_id: u32,
    pub s_gnb_ue_xnap_id: u32,
    pub admitted_drbs: Vec<u8>,
    pub s_gnb_transport_ip: Ipv4Address,
    pub s_gnb_gtp_teid: u32,
}

// ---------------------------------------------------------------------------
// Xn Peer State Machine & Engine
// ---------------------------------------------------------------------------

/// State of an Xn link to a neighboring gNodeB peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XnPeerState {
    Disconnected,
    SetupPending,
    Active,
}

/// State of a Handover procedure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoverStatus {
    Preparation,
    Execution,
    Completed,
    Cancelled,
}

/// Ongoing Handover context tracking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoverContext {
    pub source_ue_xnap_id: u32,
    pub target_ue_xnap_id: Option<u32>,
    pub target_cell_nr_cgi: u64,
    pub status: HandoverStatus,
    pub forwarding_tunnels: Vec<XnDataForwardingTunnel>,
    pub sn_status: Vec<SnStatusItem>,
}

/// Complete 3GPP TS 38.423 XnAP Protocol Engine for a gNodeB node.
pub struct XnapEngine {
    /// Local Global gNodeB ID.
    pub local_gnb_id: u32,
    /// Local node name.
    pub local_gnb_name: String,
    /// Local served cell list.
    pub served_cells: Vec<XnServedCellInfo>,
    /// State of Xn peer link.
    pub peer_state: XnPeerState,
    /// Remote peer Global gNB ID once established.
    pub peer_gnb_id: Option<u32>,
    /// Remote peer served cell inventory.
    pub peer_cells: Vec<XnServedCellInfo>,
    /// Local UE XnAP ID generator.
    pub next_ue_xnap_id: u32,
    /// Transaction ID generator.
    pub next_tid: u8,
    /// Outgoing Handover contexts indexed by source_ue_xnap_id.
    pub outgoing_handovers: HashMap<u32, HandoverContext>,
    /// Incoming Handover contexts indexed by target_ue_xnap_id.
    pub incoming_handovers: HashMap<u32, HandoverContext>,
}

impl XnapEngine {
    /// Create a new XnAP engine instance for a gNodeB.
    pub fn new(local_gnb_id: u32, local_gnb_name: &str) -> Self {
        XnapEngine {
            local_gnb_id,
            local_gnb_name: local_gnb_name.to_string(),
            served_cells: Vec::new(),
            peer_state: XnPeerState::Disconnected,
            peer_gnb_id: None,
            peer_cells: Vec::new(),
            next_ue_xnap_id: 10001,
            next_tid: 1,
            outgoing_handovers: HashMap::new(),
            incoming_handovers: HashMap::new(),
        }
    }

    /// Register local served cells to broadcast over Xn.
    pub fn register_served_cell(&mut self, cell: XnServedCellInfo) {
        self.served_cells.push(cell);
    }

    // -----------------------------------------------------------------------
    // Xn Setup Procedures (Section 8.4)
    // -----------------------------------------------------------------------

    /// Initiate Xn Setup toward a neighboring gNodeB peer.
    pub fn initiate_xn_setup(&mut self) -> Result<XnSetupRequest, &'static str> {
        if self.served_cells.is_empty() {
            return Err("Cannot initiate Xn Setup with zero served cells");
        }
        self.peer_state = XnPeerState::SetupPending;
        let tid = self.next_tid;
        self.next_tid = self.next_tid.wrapping_add(1);

        Ok(XnSetupRequest {
            transaction_id: tid,
            global_gnb_id: self.local_gnb_id,
            gnb_name: Some(self.local_gnb_name.clone()),
            served_cells: self.served_cells.clone(),
            tai_support_list: vec![1001, 1002],
        })
    }

    /// Handle incoming XnSetupRequest from peer gNodeB.
    pub fn handle_xn_setup_request(
        &mut self,
        req: &XnSetupRequest,
    ) -> Result<XnSetupResponse, XnSetupFailure> {
        if req.served_cells.is_empty() {
            return Err(XnSetupFailure {
                transaction_id: req.transaction_id,
                cause: XnCause::NoRadioResourcesAvailableInTargetCell,
            });
        }
        self.peer_state = XnPeerState::Active;
        self.peer_gnb_id = Some(req.global_gnb_id);
        self.peer_cells = req.served_cells.clone();

        Ok(XnSetupResponse {
            transaction_id: req.transaction_id,
            global_gnb_id: self.local_gnb_id,
            gnb_name: Some(self.local_gnb_name.clone()),
            served_cells: self.served_cells.clone(),
        })
    }

    /// Handle incoming XnSetupResponse from peer gNodeB.
    pub fn handle_xn_setup_response(&mut self, resp: &XnSetupResponse) -> Result<(), &'static str> {
        if self.peer_state != XnPeerState::SetupPending {
            return Err("Unexpected XnSetupResponse when not in SetupPending state");
        }
        self.peer_state = XnPeerState::Active;
        self.peer_gnb_id = Some(resp.global_gnb_id);
        self.peer_cells = resp.served_cells.clone();
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Handover Preparation Procedures (Section 8.2)
    // -----------------------------------------------------------------------

    /// (Source gNB) Build HandoverRequest to initiate an Xn-based handover.
    pub fn build_handover_request(
        &mut self,
        cause: XnCause,
        target_cell_nr_cgi: u64,
        amf_ue_ngap_id: u64,
        sessions: Vec<PduSessionResourceToBeSetup>,
        rrc_container: Vec<u8>,
    ) -> HandoverRequest {
        let source_ue_xnap_id = self.next_ue_xnap_id;
        self.next_ue_xnap_id += 1;

        let ho_ctx = HandoverContext {
            source_ue_xnap_id,
            target_ue_xnap_id: None,
            target_cell_nr_cgi,
            status: HandoverStatus::Preparation,
            forwarding_tunnels: Vec::new(),
            sn_status: Vec::new(),
        };
        self.outgoing_handovers.insert(source_ue_xnap_id, ho_ctx);

        HandoverRequest {
            source_ue_xnap_id,
            cause,
            target_cell_nr_cgi,
            guami: 0x01_0208_950,
            amf_ue_ngap_id,
            ue_security_capabilities: 0xE0E0,
            next_hop_chaining_count: 1,
            pdu_session_resources_to_setup: sessions,
            rrc_context: rrc_container,
        }
    }

    /// (Target gNB) Handle HandoverRequest: performs admission control, allocates
    /// GTP-U downlink data forwarding tunnels, and builds HandoverRequestAcknowledge.
    pub fn handle_handover_request(
        &mut self,
        req: &HandoverRequest,
        target_base_ip: Ipv4Address,
        base_teid: u32,
        rrc_reconfig_with_sync: Vec<u8>,
    ) -> Result<HandoverRequestAcknowledge, HandoverPreparationFailure> {
        // Verify target cell is served by this gNB
        let cell_found = self
            .served_cells
            .iter()
            .any(|c| c.nr_cgi == req.target_cell_nr_cgi);
        if !cell_found {
            return Err(HandoverPreparationFailure {
                source_ue_xnap_id: req.source_ue_xnap_id,
                cause: XnCause::TargetCellNotAvailable,
            });
        }

        let target_ue_xnap_id = self.next_ue_xnap_id;
        self.next_ue_xnap_id += 1;

        let mut admitted_sessions = Vec::new();
        let mut allocated_forwarding = Vec::new();
        let mut teid_counter = base_teid;

        for session in &req.pdu_session_resources_to_setup {
            let mut admitted_drbs = Vec::new();
            let mut tunnels = Vec::new();

            for drb in &session.drb_to_setup_list {
                admitted_drbs.push(drb.drb_id);
                if drb.dl_forwarding_required {
                    let tunnel = XnDataForwardingTunnel {
                        drb_id: drb.drb_id,
                        dl_forwarding_ip: target_base_ip,
                        dl_forwarding_teid: teid_counter,
                        ul_forwarding_ip: None,
                        ul_forwarding_teid: None,
                    };
                    tunnels.push(tunnel.clone());
                    allocated_forwarding.push(tunnel);
                    teid_counter += 1;
                }
            }

            admitted_sessions.push(PduSessionResourceAdmittedItem {
                pdu_session_id: session.pdu_session_id,
                target_transport_ip: target_base_ip,
                target_gtp_teid: teid_counter,
                admitted_drbs,
                forwarding_tunnels: tunnels,
            });
            teid_counter += 1;
        }

        let ho_ctx = HandoverContext {
            source_ue_xnap_id: req.source_ue_xnap_id,
            target_ue_xnap_id: Some(target_ue_xnap_id),
            target_cell_nr_cgi: req.target_cell_nr_cgi,
            status: HandoverStatus::Execution,
            forwarding_tunnels: allocated_forwarding,
            sn_status: Vec::new(),
        };
        self.incoming_handovers.insert(target_ue_xnap_id, ho_ctx);

        Ok(HandoverRequestAcknowledge {
            source_ue_xnap_id: req.source_ue_xnap_id,
            target_ue_xnap_id,
            pdu_session_resources_admitted: admitted_sessions,
            target_to_source_transparent_container: rrc_reconfig_with_sync,
        })
    }

    /// (Source gNB) Handle HandoverRequestAcknowledge: stores target UE XnAP ID,
    /// configures forwarding tunnels, and updates status to Execution.
    pub fn handle_handover_request_ack(
        &mut self,
        ack: &HandoverRequestAcknowledge,
    ) -> Result<(), &'static str> {
        let ho_ctx = self
            .outgoing_handovers
            .get_mut(&ack.source_ue_xnap_id)
            .ok_or("Handover context not found on source gNB")?;

        ho_ctx.target_ue_xnap_id = Some(ack.target_ue_xnap_id);
        ho_ctx.status = HandoverStatus::Execution;

        // Store active data forwarding tunnels
        for session in &ack.pdu_session_resources_admitted {
            for tunnel in &session.forwarding_tunnels {
                ho_ctx.forwarding_tunnels.push(tunnel.clone());
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // SN Status Transfer & Handover Execution (Section 8.2)
    // -----------------------------------------------------------------------

    /// (Source gNB) Build SN Status Transfer message with PDCP COUNT status.
    pub fn build_sn_status_transfer(
        &mut self,
        source_ue_xnap_id: u32,
        sn_status_list: Vec<SnStatusItem>,
    ) -> Option<SnStatusTransfer> {
        let ho_ctx = self.outgoing_handovers.get_mut(&source_ue_xnap_id)?;
        let target_ue_xnap_id = ho_ctx.target_ue_xnap_id?;
        ho_ctx.sn_status = sn_status_list.clone();

        Some(SnStatusTransfer {
            source_ue_xnap_id,
            target_ue_xnap_id,
            sn_status_list,
        })
    }

    /// (Target gNB) Handle SN Status Transfer: syncs PDCP sequence numbers.
    pub fn handle_sn_status_transfer(&mut self, transfer: &SnStatusTransfer) -> bool {
        let ho_ctx = match self.incoming_handovers.get_mut(&transfer.target_ue_xnap_id) {
            Some(c) => c,
            None => return false,
        };
        ho_ctx.sn_status = transfer.sn_status_list.clone();
        true
    }

    /// (Target gNB) Build UE Context Release after successful UE attachment.
    pub fn build_ue_context_release(&mut self, target_ue_xnap_id: u32) -> Option<UeContextRelease> {
        let ho_ctx = self.incoming_handovers.get_mut(&target_ue_xnap_id)?;
        ho_ctx.status = HandoverStatus::Completed;

        Some(UeContextRelease {
            source_ue_xnap_id: ho_ctx.source_ue_xnap_id,
            target_ue_xnap_id,
        })
    }

    /// (Source gNB) Handle UE Context Release: frees source UE context.
    pub fn handle_ue_context_release(&mut self, release: &UeContextRelease) -> bool {
        if let Some(mut ho_ctx) = self.outgoing_handovers.remove(&release.source_ue_xnap_id) {
            ho_ctx.status = HandoverStatus::Completed;
            true
        } else {
            false
        }
    }

    /// (Source gNB) Build Handover Cancel.
    pub fn build_handover_cancel(
        &mut self,
        source_ue_xnap_id: u32,
        cause: XnCause,
    ) -> Option<HandoverCancel> {
        let ho_ctx = self.outgoing_handovers.get_mut(&source_ue_xnap_id)?;
        ho_ctx.status = HandoverStatus::Cancelled;

        Some(HandoverCancel {
            source_ue_xnap_id,
            target_ue_xnap_id: ho_ctx.target_ue_xnap_id,
            cause,
        })
    }

    /// (Target gNB) Handle Handover Cancel: frees allocated target resources.
    pub fn handle_handover_cancel(&mut self, cancel: &HandoverCancel) -> bool {
        if let Some(target_id) = cancel.target_ue_xnap_id {
            self.incoming_handovers.remove(&target_id).is_some()
        } else {
            // Find by source_ue_xnap_id
            let to_remove: Vec<u32> = self
                .incoming_handovers
                .iter()
                .filter(|(_, ctx)| ctx.source_ue_xnap_id == cancel.source_ue_xnap_id)
                .map(|(&k, _)| k)
                .collect();
            for k in to_remove {
                self.incoming_handovers.remove(&k);
            }
            true
        }
    }

    // -----------------------------------------------------------------------
    // Dual Connectivity Procedures (Section 8.3)
    // -----------------------------------------------------------------------

    /// (Master gNB) Build S-gNB Addition Request.
    pub fn build_sgnb_addition_request(
        &mut self,
        m_gnb_ue_xnap_id: u32,
        target_cell_nr_cgi: u64,
        drbs: Vec<XnDrbItem>,
    ) -> SgNbAdditionRequest {
        SgNbAdditionRequest {
            m_gnb_ue_xnap_id,
            target_cell_nr_cgi,
            drb_to_offload_list: drbs,
        }
    }

    /// (Secondary gNB) Handle S-gNB Addition Request.
    pub fn handle_sgnb_addition_request(
        &mut self,
        req: &SgNbAdditionRequest,
        transport_ip: Ipv4Address,
        base_teid: u32,
    ) -> SgNbAdditionRequestAcknowledge {
        let s_gnb_ue_xnap_id = self.next_ue_xnap_id;
        self.next_ue_xnap_id += 1;

        let admitted_drbs: Vec<u8> = req.drb_to_offload_list.iter().map(|d| d.drb_id).collect();

        SgNbAdditionRequestAcknowledge {
            m_gnb_ue_xnap_id: req.m_gnb_ue_xnap_id,
            s_gnb_ue_xnap_id,
            admitted_drbs,
            s_gnb_transport_ip: transport_ip,
            s_gnb_gtp_teid: base_teid,
        }
    }
}

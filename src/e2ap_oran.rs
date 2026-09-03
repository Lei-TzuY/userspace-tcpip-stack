//! O-RAN Alliance WG3 E2 Application Protocol (E2AP) Engine.
//!
//! Implements the E2 control interface over SCTP port 36421 connecting the
//! Near-Real-Time RAN Intelligent Controller (Near-RT RIC) and E2 Nodes
//! (gNB-O-DU, gNB-O-CU-CP, gNB-O-CU-UP). Supports:
//! - E2 Setup and RAN Function service model negotiation (E2SM-KPM, E2SM-RC).
//! - RIC Subscription for periodic/event-driven RAN telemetry and closed-loop control.
//! - RIC Indication delivering Key Performance Measurement (KPM) PRB usage and throughput metrics.
//! - RIC Control enforcing real-time slicing PRB quota and radio resource optimization.

use std::collections::HashMap;

/// Default SCTP port for O-RAN WG3 E2AP.
pub const E2AP_SCTP_PORT: u16 = 36421;

/// Elementary Procedure Codes per O-RAN.WG3.E2AP Section 9.3.1.
pub const E2AP_PROC_E2_SETUP: u8 = 1;
pub const E2AP_PROC_RIC_SUBSCRIPTION: u8 = 201;
pub const E2AP_PROC_RIC_SUBSCRIPTION_DELETE: u8 = 202;
pub const E2AP_PROC_RIC_CONTROL: u8 = 204;
pub const E2AP_PROC_RIC_INDICATION: u8 = 205;

/// Well-known O-RAN Service Model (E2SM) RAN Function IDs.
pub const RAN_FUNCTION_ID_KPM: u16 = 1; // Key Performance Measurement
pub const RAN_FUNCTION_ID_RC: u16 = 2; // RAN Control
pub const RAN_FUNCTION_ID_NI: u16 = 3; // Network Interface

/// Type of E2 Node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum E2NodeType {
    ODu,
    OCuCp,
    OCuUp,
    OeNb,
}

/// Global E2 Node Identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalE2NodeId {
    pub node_type: E2NodeType,
    pub node_id: u64,
    pub plmn_id: [u8; 3],
}

/// RAN Function Service Model definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RanFunctionDefinition {
    pub ran_function_id: u16,
    pub ran_function_revision: u16,
    pub description: String,
}

/// E2 Setup Request (E2 Node -> Near-RT RIC).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct E2SetupRequest {
    pub transaction_id: u8,
    pub global_e2_node_id: GlobalE2NodeId,
    pub ran_functions_added: Vec<RanFunctionDefinition>,
}

/// E2 Setup Response (Near-RT RIC -> E2 Node).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct E2SetupResponse {
    pub transaction_id: u8,
    pub global_ric_id: u32,
    pub ran_functions_accepted: Vec<u16>,
    pub ran_functions_rejected: Vec<u16>,
}

/// E2 Setup Failure (Near-RT RIC -> E2 Node).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct E2SetupFailure {
    pub transaction_id: u8,
    pub cause: &'static str,
}

/// RIC Request Identifier (Requestor ID + Instance ID).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RicRequestId {
    pub ric_requestor_id: u16,
    pub ric_instance_id: u16,
}

/// RIC Action Type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RicActionType {
    Report,
    Insert,
    Policy,
}

/// Action Item within a RIC Subscription.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RicActionItem {
    pub ric_action_id: u8,
    pub ric_action_type: RicActionType,
    pub ric_action_definition: Option<Vec<u8>>,
}

/// RIC Subscription Request (Near-RT RIC -> E2 Node).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RicSubscriptionRequest {
    pub ric_request_id: RicRequestId,
    pub ran_function_id: u16,
    pub event_trigger_period_ms: u32,
    pub actions: Vec<RicActionItem>,
}

/// RIC Subscription Response (E2 Node -> Near-RT RIC).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RicSubscriptionResponse {
    pub ric_request_id: RicRequestId,
    pub ran_function_id: u16,
    pub actions_admitted: Vec<u8>,
    pub actions_not_admitted: Vec<(u8, &'static str)>,
}

/// RIC Indication Type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RicIndicationType {
    Report,
    Insert,
}

/// Telemetry metrics for E2SM-KPM.
#[derive(Debug, Clone, PartialEq)]
pub struct KpmMetricsPayload {
    pub cell_id: u64,
    pub dl_prb_usage_ppm: u32, // PRB usage in parts-per-million (0..1_000_000)
    pub ul_prb_usage_ppm: u32,
    pub dl_throughput_mbps: f64,
    pub ul_throughput_mbps: f64,
    pub active_ue_count: u32,
    pub avg_packet_delay_us: u32,
}

/// RIC Indication message streaming telemetry to Near-RT RIC.
#[derive(Debug, Clone, PartialEq)]
pub struct RicIndication {
    pub ric_request_id: RicRequestId,
    pub ran_function_id: u16,
    pub ric_action_id: u8,
    pub ric_indication_sn: u32,
    pub ric_indication_type: RicIndicationType,
    pub kpm_metrics: Option<KpmMetricsPayload>,
}

/// RIC Control Request from Near-RT RIC / xApp to E2 Node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RicControlRequest {
    pub ric_request_id: RicRequestId,
    pub ran_function_id: u16,
    pub target_slice_sst: u8,
    pub target_slice_sd: Option<[u8; 3]>,
    pub allocated_prb_quota_ppm: u32,
    pub ack_request: bool,
}

/// RIC Control Acknowledge from E2 Node to Near-RT RIC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RicControlAcknowledge {
    pub ric_request_id: RicRequestId,
    pub ran_function_id: u16,
    pub status: &'static str,
}

/// Role in the E2 Interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum E2apRole {
    NearRtRic,
    E2Node,
}

/// E2 Interface Connection State.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum E2apState {
    Idle,
    SetupPending,
    Active,
}

/// O-RAN WG3 E2AP Engine (Near-RT RIC / E2 Node).
#[derive(Debug, Clone)]
pub struct E2apEngine {
    pub role: E2apRole,
    pub state: E2apState,
    pub node_id: GlobalE2NodeId,
    pub supported_ran_functions: Vec<RanFunctionDefinition>,
    pub accepted_ran_functions: Vec<u16>,
    pub active_subscriptions: HashMap<RicRequestId, RicSubscriptionRequest>,
    pub slice_prb_quotas: HashMap<u8, u32>, // SST -> PRB quota in ppm
    next_tx_id: u8,
    next_indication_sn: u32,
}

impl E2apEngine {
    pub fn new(role: E2apRole, node_id: GlobalE2NodeId) -> Self {
        Self {
            role,
            state: E2apState::Idle,
            node_id,
            supported_ran_functions: Vec::new(),
            accepted_ran_functions: Vec::new(),
            active_subscriptions: HashMap::new(),
            slice_prb_quotas: HashMap::new(),
            next_tx_id: 1,
            next_indication_sn: 1,
        }
    }

    /// Generates E2SetupRequest (E2 Node -> Near-RT RIC).
    pub fn initiate_e2_setup(
        &mut self,
        ran_functions: Vec<RanFunctionDefinition>,
    ) -> E2SetupRequest {
        self.state = E2apState::SetupPending;
        self.supported_ran_functions = ran_functions.clone();
        let tx_id = self.next_tx_id;
        self.next_tx_id = self.next_tx_id.wrapping_add(1);

        E2SetupRequest {
            transaction_id: tx_id,
            global_e2_node_id: self.node_id.clone(),
            ran_functions_added: ran_functions,
        }
    }

    /// Handles E2SetupRequest on Near-RT RIC.
    pub fn handle_e2_setup_request(
        &mut self,
        req: &E2SetupRequest,
    ) -> Result<E2SetupResponse, E2SetupFailure> {
        if self.role != E2apRole::NearRtRic {
            return Err(E2SetupFailure {
                transaction_id: req.transaction_id,
                cause: "Only Near-RT RIC can process E2SetupRequest",
            });
        }

        if req.ran_functions_added.is_empty() {
            return Err(E2SetupFailure {
                transaction_id: req.transaction_id,
                cause: "No RAN functions advertised by E2 Node",
            });
        }

        let mut accepted = Vec::new();
        let mut rejected = Vec::new();

        for func in &req.ran_functions_added {
            // Admit KPM and RC service models
            if func.ran_function_id == RAN_FUNCTION_ID_KPM
                || func.ran_function_id == RAN_FUNCTION_ID_RC
            {
                accepted.push(func.ran_function_id);
            } else {
                rejected.push(func.ran_function_id);
            }
        }

        self.accepted_ran_functions = accepted.clone();
        self.state = E2apState::Active;

        Ok(E2SetupResponse {
            transaction_id: req.transaction_id,
            global_ric_id: 0x0001_0001,
            ran_functions_accepted: accepted,
            ran_functions_rejected: rejected,
        })
    }

    /// Handles E2SetupResponse on E2 Node.
    pub fn handle_e2_setup_response(&mut self, resp: &E2SetupResponse) -> Result<(), &'static str> {
        if self.role != E2apRole::E2Node {
            return Err("Only E2 Node can process E2SetupResponse");
        }
        if self.state != E2apState::SetupPending {
            return Err("Received E2SetupResponse while not in SetupPending state");
        }

        self.accepted_ran_functions = resp.ran_functions_accepted.clone();
        self.state = E2apState::Active;
        Ok(())
    }

    /// Handles RIC Subscription Request on E2 Node.
    pub fn handle_subscription_request(
        &mut self,
        req: &RicSubscriptionRequest,
    ) -> Result<RicSubscriptionResponse, &'static str> {
        if self.role != E2apRole::E2Node {
            return Err("Only E2 Node can handle RicSubscriptionRequest");
        }
        if self.state != E2apState::Active {
            return Err("E2 interface is not active");
        }

        if !self.accepted_ran_functions.contains(&req.ran_function_id) {
            return Err("RAN function not admitted during E2 setup");
        }

        let mut admitted = Vec::new();
        let not_admitted = Vec::new();

        for act in &req.actions {
            admitted.push(act.ric_action_id);
        }

        self.active_subscriptions
            .insert(req.ric_request_id, req.clone());

        Ok(RicSubscriptionResponse {
            ric_request_id: req.ric_request_id,
            ran_function_id: req.ran_function_id,
            actions_admitted: admitted,
            actions_not_admitted: not_admitted,
        })
    }

    /// Emits RIC Indication with KPM telemetry metrics (E2 Node -> Near-RT RIC).
    pub fn emit_kpm_indication(
        &mut self,
        req_id: RicRequestId,
        action_id: u8,
        metrics: KpmMetricsPayload,
    ) -> Result<RicIndication, &'static str> {
        if self.role != E2apRole::E2Node {
            return Err("Only E2 Node can emit RIC Indication");
        }
        if self.state != E2apState::Active {
            return Err("E2 interface is not active");
        }

        let sub = self
            .active_subscriptions
            .get(&req_id)
            .ok_or("Subscription does not exist for specified RicRequestId")?;

        let sn = self.next_indication_sn;
        self.next_indication_sn = self.next_indication_sn.wrapping_add(1);

        Ok(RicIndication {
            ric_request_id: req_id,
            ran_function_id: sub.ran_function_id,
            ric_action_id: action_id,
            ric_indication_sn: sn,
            ric_indication_type: RicIndicationType::Report,
            kpm_metrics: Some(metrics),
        })
    }

    /// Handles RIC Control Request on E2 Node.
    pub fn handle_control_request(
        &mut self,
        ctrl: &RicControlRequest,
    ) -> Result<Option<RicControlAcknowledge>, &'static str> {
        if self.role != E2apRole::E2Node {
            return Err("Only E2 Node can handle RicControlRequest");
        }
        if self.state != E2apState::Active {
            return Err("E2 interface is not active");
        }

        // Apply dynamic PRB quota update for the target network slice
        self.slice_prb_quotas
            .insert(ctrl.target_slice_sst, ctrl.allocated_prb_quota_ppm);

        if ctrl.ack_request {
            Ok(Some(RicControlAcknowledge {
                ric_request_id: ctrl.ric_request_id,
                ran_function_id: ctrl.ran_function_id,
                status: "Success",
            }))
        } else {
            Ok(None)
        }
    }
}

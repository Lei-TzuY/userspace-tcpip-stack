//! 3GPP TS 23.316 / TS 29.502 / BBF TR-456 Release 17 5G-Wireline Convergence (5G-WWC) Engine.
//!
//! Implements 5G Wireline Access Gateway Function (W-AGF):
//! - Fixed Residential Gateway (5G-RG & Legacy FN-RG) convergence into 5G Core
//! - Global Line Identifier (GLI - TS 23.003 Section 28.15) and VLAN-to-SUPI mapping
//! - Wireline N2 (NGAP) signaling towards AMF & N3 (GTP-U) user plane towards UPF
//! - Fixed-to-Mobile QoS mapping (802.1p CoS / IP DSCP to 5QI & QFI flows)
//! - Line connection lifecycle state machine and GTP-U framing encapsulation

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// 5G-WWC W-AGF Enums & Data Structures (TS 23.316 Section 4 / BBF TR-456)
// ---------------------------------------------------------------------------

/// Residential Gateway Category (TS 23.316 Section 4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RgType {
    /// 5G-aware Residential Gateway (natively communicates 5G NAS over Ethernet).
    Rg5G,
    /// Fixed Network Residential Gateway (legacy GPON/DSL router; W-AGF proxies NAS).
    FnRg,
}

/// Global Line Identifier (GLI - TS 23.003 Section 28.15).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GlobalLineId {
    pub operator_id: [u8; 3], // Broadband Forum Operator ID
    pub circuit_id: String,   // Access node circuit/remote ID
    pub s_vlan: u16,          // Service VLAN (0..4095)
    pub c_vlan: u16,          // Customer VLAN (0..4095)
}

impl GlobalLineId {
    pub fn to_string(&self) -> String {
        format!(
            "GLI-{:02x}{:02x}{:02x}:{}-SVLAN{}-CVLAN{}",
            self.operator_id[0],
            self.operator_id[1],
            self.operator_id[2],
            self.circuit_id,
            self.s_vlan,
            self.c_vlan
        )
    }
}

/// Wireline Session State Machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WirelineSessionState {
    LineDiscovered,
    NasRegistered,
    PduActive,
    Terminated,
}

/// Fixed-to-Mobile QoS Mapping Rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QosMappingRule {
    pub cos_8021p: u8, // 0..7
    pub target_5qi: u8,
    pub target_qfi: u8,
}

/// Wireline Subscriber Session Context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WirelineSessionContext {
    pub session_id: String,
    pub rg_type: RgType,
    pub line_id: GlobalLineId,
    pub supi: String,
    pub ran_ue_ngap_id: u64,
    pub amf_ue_ngap_id: Option<u64>,
    pub wagf_teid: u32,
    pub upf_teid: Option<u32>,
    pub state: WirelineSessionState,
    pub active_5qi: u8,
    pub active_qfi: u8,
}

/// W-AGF Error Types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WagfError {
    SessionNotFound,
    InvalidSessionState(&'static str),
    QosMappingNotFound,
}

// ---------------------------------------------------------------------------
// Top-Level 5G W-AGF Engine
// ---------------------------------------------------------------------------

/// 5G Wireline Access Gateway Function (W-AGF).
pub struct WagfEngine {
    pub wagf_id: String,
    pub next_ran_ngap_counter: u64,
    pub next_teid_counter: u32,
    /// Active Wireline Sessions: session_id -> WirelineSessionContext
    pub sessions: HashMap<String, WirelineSessionContext>,
    /// Line to Session lookup: GlobalLineId -> session_id
    pub line_to_session: HashMap<GlobalLineId, String>,
    /// QoS Mapping Rules: cos_8021p -> QosMappingRule
    pub qos_rules: HashMap<u8, QosMappingRule>,
}

impl WagfEngine {
    /// Create a new 5G W-AGF engine instance.
    pub fn new(wagf_id: &str) -> Self {
        let mut qos_rules = HashMap::new();
        // Default BBF TR-456 standard QoS mappings
        qos_rules.insert(
            0,
            QosMappingRule {
                cos_8021p: 0,
                target_5qi: 9, // Best Effort Internet
                target_qfi: 1,
            },
        );
        qos_rules.insert(
            4,
            QosMappingRule {
                cos_8021p: 4,
                target_5qi: 75, // Managed Video / IPTV
                target_qfi: 2,
            },
        );
        qos_rules.insert(
            6,
            QosMappingRule {
                cos_8021p: 6,
                target_5qi: 1, // Fixed VoIP Voice
                target_qfi: 3,
            },
        );

        WagfEngine {
            wagf_id: wagf_id.to_string(),
            next_ran_ngap_counter: 1000,
            next_teid_counter: 0x10000001,
            sessions: HashMap::new(),
            line_to_session: HashMap::new(),
            qos_rules,
        }
    }

    /// Step 1: Detect physical line connectivity (GPON/DSL) and initiate N2 Wireline Registration.
    pub fn register_line_discovery(
        &mut self,
        rg_type: RgType,
        line_id: GlobalLineId,
        supi: &str,
    ) -> String {
        let ran_ngap_id = self.next_ran_ngap_counter;
        self.next_ran_ngap_counter += 1;

        let wagf_teid = self.next_teid_counter;
        self.next_teid_counter += 1;

        let session_id = format!("wagf-sess-{}", line_id.to_string());

        let ctx = WirelineSessionContext {
            session_id: session_id.clone(),
            rg_type,
            line_id: line_id.clone(),
            supi: supi.to_string(),
            ran_ue_ngap_id: ran_ngap_id,
            amf_ue_ngap_id: None,
            wagf_teid,
            upf_teid: None,
            state: WirelineSessionState::LineDiscovered,
            active_5qi: 9,
            active_qfi: 1,
        };

        self.line_to_session.insert(line_id, session_id.clone());
        self.sessions.insert(session_id.clone(), ctx);

        session_id
    }

    /// Step 2: AMF confirms N2 Registration and assigns AMF UE NGAP ID.
    pub fn confirm_amf_registration(
        &mut self,
        session_id: &str,
        amf_ue_ngap_id: u64,
    ) -> Result<(), WagfError> {
        let sess = self
            .sessions
            .get_mut(session_id)
            .ok_or(WagfError::SessionNotFound)?;
        sess.amf_ue_ngap_id = Some(amf_ue_ngap_id);
        sess.state = WirelineSessionState::NasRegistered;
        Ok(())
    }

    /// Step 3: Establish Wireline PDU Session & N3 GTP-U Tunnel to UPF.
    pub fn complete_pdu_session_setup(
        &mut self,
        session_id: &str,
        upf_teid: u32,
        cos_8021p: u8,
    ) -> Result<(), WagfError> {
        let qos = self
            .qos_rules
            .get(&cos_8021p)
            .cloned()
            .ok_or(WagfError::QosMappingNotFound)?;

        let sess = self
            .sessions
            .get_mut(session_id)
            .ok_or(WagfError::SessionNotFound)?;
        if sess.state != WirelineSessionState::NasRegistered {
            return Err(WagfError::InvalidSessionState(
                "Session must be NasRegistered before establishing PDU session",
            ));
        }

        sess.upf_teid = Some(upf_teid);
        sess.active_5qi = qos.target_5qi;
        sess.active_qfi = qos.target_qfi;
        sess.state = WirelineSessionState::PduActive;

        Ok(())
    }

    /// Encapsulate Fixed Ethernet/IP packet into 3GPP N3 GTP-U frame.
    pub fn encapsulate_fixed_to_n3(
        &self,
        session_id: &str,
        fixed_payload: &[u8],
    ) -> Result<Vec<u8>, WagfError> {
        let sess = self
            .sessions
            .get(session_id)
            .ok_or(WagfError::SessionNotFound)?;
        if sess.state != WirelineSessionState::PduActive {
            return Err(WagfError::InvalidSessionState("PDU session is not active"));
        }

        let upf_teid = sess.upf_teid.unwrap_or(0);

        // GTP-U Header (8 bytes):
        // Flags: 0x30 (v1, Protocol GTP)
        // Msg Type: 0xFF (G-PDU)
        // Length: 2 bytes (payload length)
        // TEID: 4 bytes
        let mut gtp_packet = Vec::with_capacity(8 + fixed_payload.len());
        gtp_packet.push(0x30); // Flags
        gtp_packet.push(0xFF); // G-PDU Message Type
        gtp_packet.extend_from_slice(&(fixed_payload.len() as u16).to_be_bytes());
        gtp_packet.extend_from_slice(&upf_teid.to_be_bytes());
        gtp_packet.extend_from_slice(fixed_payload);

        Ok(gtp_packet)
    }

    /// Terminate a wireline subscriber line session.
    pub fn terminate_line_session(&mut self, session_id: &str) -> Result<(), WagfError> {
        let sess = self
            .sessions
            .remove(session_id)
            .ok_or(WagfError::SessionNotFound)?;
        self.line_to_session.remove(&sess.line_id);
        Ok(())
    }
}

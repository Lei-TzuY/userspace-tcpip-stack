//! 3GPP TS 23.501 / TS 23.502 / TS 24.502 / TS 33.501 Release 17 5G Trusted Non-3GPP Gateway Function (TNGF) Engine.
//!
//! Implements Carrier Wi-Fi 6 / Passpoint Trusted Non-3GPP Access into 5G Core:
//! - Ta interface termination (EAP-5G over IEEE 802.1X / WPA3-Enterprise)
//! - N2 (NGAP) signaling relay towards AMF without IPsec IKEv2 overhead
//! - Lightweight GRE (RFC 2784 / RFC 2890) user plane encapsulation between UE and TNGF
//! - N3 (GTP-U) user plane bridge towards UPF with PDU Session / QFI mapping
//! - Trusted Non-3GPP Access Point (TNAP) association management and session lifecycle

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// 5G TNGF Enums & Data Structures (TS 23.501 Section 4.2.8.2 / TS 24.502)
// ---------------------------------------------------------------------------

/// Trusted Access Type (TS 23.501 Section 4.2.8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustedAccessType {
    CarrierWifiPasspoint,
    EnterpriseWpa3,
}

/// Trusted Non-3GPP Access Point (TNAP) Information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TnapInfo {
    pub tnap_id: String,
    pub ssid: String,
    pub bssid: [u8; 6],
    pub access_type: TrustedAccessType,
}

/// TNGF Session State Machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TngfSessionState {
    AuthenticatingEap5g,
    AuthenticatedNasRegistered,
    GreSessionActive,
    Terminated,
}

/// TNGF Subscriber Session Context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TngfSessionContext {
    pub session_id: String,
    pub supi: String,
    pub tnap_info: TnapInfo,
    pub ran_ue_ngap_id: u64,
    pub amf_ue_ngap_id: Option<u64>,
    pub gre_key: u32,
    pub upf_teid: Option<u32>,
    pub tngf_n3_teid: u32,
    pub qfi: u8,
    pub state: TngfSessionState,
}

/// TNGF Error Types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TngfError {
    SessionNotFound,
    InvalidSessionState(&'static str),
    InvalidGrePacket(&'static str),
}

// ---------------------------------------------------------------------------
// Top-Level 5G-TNGF Engine
// ---------------------------------------------------------------------------

/// 5G Trusted Non-3GPP Gateway Function (TNGF).
pub struct TngfEngine {
    pub tngf_id: String,
    pub next_ran_ngap_counter: u64,
    pub next_gre_key_counter: u32,
    pub next_n3_teid_counter: u32,
    /// Active Sessions: session_id -> TngfSessionContext
    pub sessions: HashMap<String, TngfSessionContext>,
    /// GRE Key lookup: gre_key -> session_id
    pub gre_key_to_session: HashMap<u32, String>,
}

impl TngfEngine {
    /// Create a new 5G-TNGF engine instance.
    pub fn new(tngf_id: &str) -> Self {
        TngfEngine {
            tngf_id: tngf_id.to_string(),
            next_ran_ngap_counter: 5000,
            next_gre_key_counter: 0x80000001,
            next_n3_teid_counter: 0x90000001,
            sessions: HashMap::new(),
            gre_key_to_session: HashMap::new(),
        }
    }

    /// Step 1: UE attaches via Trusted Wi-Fi (Ta interface) and initiates EAP-5G / NAS Registration.
    pub fn initiate_eap5g_access(
        &mut self,
        supi: &str,
        tnap_info: TnapInfo,
        _nas_pdu: &[u8],
    ) -> String {
        let ran_ngap_id = self.next_ran_ngap_counter;
        self.next_ran_ngap_counter += 1;

        let gre_key = self.next_gre_key_counter;
        self.next_gre_key_counter += 1;

        let n3_teid = self.next_n3_teid_counter;
        self.next_n3_teid_counter += 1;

        let session_id = format!("tngf-sess-{}-{}", supi, tnap_info.tnap_id);

        let ctx = TngfSessionContext {
            session_id: session_id.clone(),
            supi: supi.to_string(),
            tnap_info,
            ran_ue_ngap_id: ran_ngap_id,
            amf_ue_ngap_id: None,
            gre_key,
            upf_teid: None,
            tngf_n3_teid: n3_teid,
            qfi: 1,
            state: TngfSessionState::AuthenticatingEap5g,
        };

        self.gre_key_to_session.insert(gre_key, session_id.clone());
        self.sessions.insert(session_id.clone(), ctx);

        session_id
    }

    /// Step 2: AMF confirms N2 Registration and assigns AMF UE NGAP ID.
    pub fn confirm_amf_registration(
        &mut self,
        session_id: &str,
        amf_ue_ngap_id: u64,
    ) -> Result<(), TngfError> {
        let sess = self
            .sessions
            .get_mut(session_id)
            .ok_or(TngfError::SessionNotFound)?;
        sess.amf_ue_ngap_id = Some(amf_ue_ngap_id);
        sess.state = TngfSessionState::AuthenticatedNasRegistered;
        Ok(())
    }

    /// Step 3: Establish Trusted Non-3GPP PDU Session and activate GRE / N3 user planes.
    pub fn establish_pdu_session(
        &mut self,
        session_id: &str,
        upf_teid: u32,
        qfi: u8,
    ) -> Result<u32, TngfError> {
        let sess = self
            .sessions
            .get_mut(session_id)
            .ok_or(TngfError::SessionNotFound)?;
        if sess.state != TngfSessionState::AuthenticatedNasRegistered {
            return Err(TngfError::InvalidSessionState(
                "Session must be AuthenticatedNasRegistered before PDU session setup",
            ));
        }

        sess.upf_teid = Some(upf_teid);
        sess.qfi = qfi;
        sess.state = TngfSessionState::GreSessionActive;

        Ok(sess.gre_key)
    }

    /// Encapsulate user payload into standard RFC 2784 / RFC 2890 GRE packet with 32-bit Key.
    pub fn encapsulate_user_packet_to_gre(
        &self,
        session_id: &str,
        user_payload: &[u8],
    ) -> Result<Vec<u8>, TngfError> {
        let sess = self
            .sessions
            .get(session_id)
            .ok_or(TngfError::SessionNotFound)?;
        if sess.state != TngfSessionState::GreSessionActive {
            return Err(TngfError::InvalidSessionState("GRE session is not active"));
        }

        // GRE Header with Key flag (RFC 2890):
        // Flags (2 bytes): 0x2000 (Bit 2: Key Present)
        // Protocol Type (2 bytes): 0x0800 (IPv4) or 0x86DD (IPv6)
        // Key (4 bytes): 32-bit gre_key
        let mut gre_frame = Vec::with_capacity(8 + user_payload.len());
        gre_frame.push(0x20); // Flag: Key Present
        gre_frame.push(0x00);
        gre_frame.push(0x08); // Protocol: IPv4 (0x0800)
        gre_frame.push(0x00);
        gre_frame.extend_from_slice(&sess.gre_key.to_be_bytes());
        gre_frame.extend_from_slice(user_payload);

        Ok(gre_frame)
    }

    /// Translate inbound GRE frame from UE into N3 GTP-U frame towards UPF.
    pub fn forward_gre_to_n3_gtpu(&self, gre_frame: &[u8]) -> Result<Vec<u8>, TngfError> {
        if gre_frame.len() < 8 {
            return Err(TngfError::InvalidGrePacket("GRE frame is too short"));
        }

        // Check Key Present flag
        if (gre_frame[0] & 0x20) == 0 {
            return Err(TngfError::InvalidGrePacket("GRE Key flag missing"));
        }

        let gre_key = u32::from_be_bytes([gre_frame[4], gre_frame[5], gre_frame[6], gre_frame[7]]);
        let session_id = self
            .gre_key_to_session
            .get(&gre_key)
            .ok_or(TngfError::SessionNotFound)?;

        let sess = self
            .sessions
            .get(session_id)
            .ok_or(TngfError::SessionNotFound)?;
        if sess.state != TngfSessionState::GreSessionActive {
            return Err(TngfError::InvalidSessionState(
                "Session is not in GreSessionActive state",
            ));
        }

        let upf_teid = sess.upf_teid.unwrap_or(0);
        let user_payload = &gre_frame[8..];

        // GTP-U Header (8 bytes):
        let mut gtp_packet = Vec::with_capacity(8 + user_payload.len());
        gtp_packet.push(0x30); // GTPv1 G-PDU
        gtp_packet.push(0xFF); // Msg Type 255
        gtp_packet.extend_from_slice(&(user_payload.len() as u16).to_be_bytes());
        gtp_packet.extend_from_slice(&upf_teid.to_be_bytes());
        gtp_packet.extend_from_slice(user_payload);

        Ok(gtp_packet)
    }

    /// Terminate a Trusted Non-3GPP subscriber session.
    pub fn terminate_session(&mut self, session_id: &str) -> Result<(), TngfError> {
        let sess = self
            .sessions
            .remove(session_id)
            .ok_or(TngfError::SessionNotFound)?;
        self.gre_key_to_session.remove(&sess.gre_key);
        Ok(())
    }
}

//! 3GPP TS 24.502 / TS 23.501 / TS 33.501 5G Non-3GPP Interworking Function (N3IWF) Engine.
//!
//! Implements 5G Standalone untrusted Wi-Fi / Non-3GPP access interworking:
//! - NWu Interface (UE <-> N3IWF):
//!   - IKEv2 / EAP-5G signaling encapsulation for 5G NAS messages
//!   - Key derivation of child IPsec SA keys (K_enc, K_int) from K_N3IWF root key
//!   - IPsec ESP tunnel encapsulation / decapsulation with Integrity Check Values (ICV)
//! - N2 Interface (N3IWF <-> AMF):
//!   - NGAP transport bridging 5G-NAS-PDU payloads between EAP-5G and AMF
//!   - PDU Session Resource Setup handling (allocating GTP-U TEIDs and Child SA SPIs)
//! - N3 Interface (N3IWF <-> UPF):
//!   - User plane bidirectional translation:
//!     - Uplink: IPsec ESP (NWu) -> GTP-U (N3 to UPF)
//!     - Downlink: GTP-U (N3 from UPF) -> IPsec ESP (NWu to UE)

use std::collections::HashMap;

use crate::ipv4::Ipv4Address;

// ---------------------------------------------------------------------------
// 5G N3IWF Enums & Data Structures
// ---------------------------------------------------------------------------

/// EAP-5G Packet Types (TS 24.502 Section 9.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Eap5gType {
    Start,
    NasPdu,
    Notification,
    Success,
}

/// EAP-5G Encapsulated Message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eap5gMessage {
    pub message_type: Eap5gType,
    pub nas_pdu: Vec<u8>,
}

/// IPsec Child Security Association (SA) for a PDU Session / QoS Flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct N3iwfChildSa {
    pub spi_in: u32,
    pub spi_out: u32,
    pub pdu_session_id: u8,
    pub qfi: u8,
    pub k_enc: [u8; 16],
    pub k_int: [u8; 16],
}

/// Active PDU session mapping in N3IWF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct N3iwfPduSession {
    pub pdu_session_id: u8,
    pub qfi: u8,
    pub upf_teid: u32,
    pub upf_ip: Ipv4Address,
    pub n3_dl_teid: u32,
    pub child_spi_in: u32,
    pub child_spi_out: u32,
}

/// UE Context maintained within N3IWF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct N3iwfUeContext {
    pub ue_ctx_id: u32,
    pub ran_ue_ngap_id: u32,
    pub amf_ue_ngap_id: Option<u32>,
    pub ue_untrusted_ip: Ipv4Address,
    pub assigned_virtual_ip: Option<Ipv4Address>,
    pub k_n3iwf: Option<[u8; 32]>,
    pub authenticated: bool,
    pub child_sas: HashMap<u32, N3iwfChildSa>, // Keyed by spi_in
    pub pdu_sessions: HashMap<u8, N3iwfPduSession>, // Keyed by pdu_session_id
}

/// IPsec ESP Packet (RFC 4303).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EspPacket {
    pub spi: u32,
    pub seq_num: u32,
    pub encrypted_payload: Vec<u8>,
    pub icv: [u8; 16], // Integrity Check Value
}

/// GTP-U Packet (3GPP TS 29.281).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GtpuPacket {
    pub teid: u32,
    pub qfi: u8,
    pub payload: Vec<u8>,
}

/// N3IWF Processing Errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum N3iwfError {
    UeNotFound,
    PduSessionNotFound,
    SecurityAssociationNotFound,
    IntegrityCheckFailed,
    Unauthenticated,
}

// ---------------------------------------------------------------------------
// Top-Level N3IWF Engine
// ---------------------------------------------------------------------------

/// 5G Non-3GPP Interworking Function (N3IWF) Engine.
pub struct N3iwfEngine {
    pub n3iwf_ip: Ipv4Address,
    pub next_ue_id: u32,
    pub next_ran_ngap_id: u32,
    pub next_spi: u32,
    pub next_dl_teid: u32,
    /// Contexts: ue_untrusted_ip -> N3iwfUeContext
    pub ue_contexts_by_ip: HashMap<Ipv4Address, N3iwfUeContext>,
    /// Global routing lookup: spi_in -> ue_untrusted_ip
    pub spi_in_to_ue: HashMap<u32, Ipv4Address>,
    /// Global routing lookup: n3_dl_teid -> (ue_untrusted_ip, pdu_session_id)
    pub dl_teid_to_ue: HashMap<u32, (Ipv4Address, u8)>,
}

impl N3iwfEngine {
    /// Create a new N3IWF engine.
    pub fn new(n3iwf_ip: Ipv4Address) -> Self {
        N3iwfEngine {
            n3iwf_ip,
            next_ue_id: 1,
            next_ran_ngap_id: 100,
            next_spi: 0x8000_0001,
            next_dl_teid: 0x5000_0001,
            ue_contexts_by_ip: HashMap::new(),
            spi_in_to_ue: HashMap::new(),
            dl_teid_to_ue: HashMap::new(),
        }
    }

    // -----------------------------------------------------------------------
    // IKEv2 / EAP-5G Signaling Handshake (TS 24.502)
    // -----------------------------------------------------------------------

    /// Handle IKE_SA_INIT: Register new UE untrusted connection.
    pub fn handle_ike_sa_init(&mut self, ue_untrusted_ip: Ipv4Address) -> u32 {
        let ue_id = self.next_ue_id;
        self.next_ue_id += 1;
        let ran_ngap_id = self.next_ran_ngap_id;
        self.next_ran_ngap_id += 1;

        let ctx = N3iwfUeContext {
            ue_ctx_id: ue_id,
            ran_ue_ngap_id: ran_ngap_id,
            amf_ue_ngap_id: None,
            ue_untrusted_ip,
            assigned_virtual_ip: None,
            k_n3iwf: None,
            authenticated: false,
            child_sas: HashMap::new(),
            pdu_sessions: HashMap::new(),
        };

        self.ue_contexts_by_ip.insert(ue_untrusted_ip, ctx);

        ue_id
    }

    /// Complete 5G authentication using K_N3IWF root key received from AMF.
    pub fn complete_authentication_and_establish_sa(
        &mut self,
        ue_untrusted_ip: Ipv4Address,
        k_n3iwf: [u8; 32],
        virtual_ip: Ipv4Address,
    ) -> Result<(u32, u32), N3iwfError> {
        let ctx = self
            .ue_contexts_by_ip
            .get_mut(&ue_untrusted_ip)
            .ok_or(N3iwfError::UeNotFound)?;

        ctx.k_n3iwf = Some(k_n3iwf);
        ctx.assigned_virtual_ip = Some(virtual_ip);
        ctx.authenticated = true;

        // Derive Child SA encryption and integrity keys (K_enc, K_int)
        let mut k_enc = [0u8; 16];
        let mut k_int = [0u8; 16];
        k_enc.copy_from_slice(&k_n3iwf[0..16]);
        k_int.copy_from_slice(&k_n3iwf[16..32]);

        let spi_in = self.next_spi;
        self.next_spi += 1;
        let spi_out = self.next_spi;
        self.next_spi += 1;

        let child_sa = N3iwfChildSa {
            spi_in,
            spi_out,
            pdu_session_id: 1, // Default PDU session
            qfi: 1,
            k_enc,
            k_int,
        };

        ctx.child_sas.insert(spi_in, child_sa);
        self.spi_in_to_ue.insert(spi_in, ue_untrusted_ip);

        Ok((spi_in, spi_out))
    }

    // -----------------------------------------------------------------------
    // N2 PDU Session Resource Setup (N3IWF <-> AMF)
    // -----------------------------------------------------------------------

    /// Setup PDU Session Resource with UPF parameters.
    pub fn setup_pdu_session(
        &mut self,
        ue_untrusted_ip: Ipv4Address,
        pdu_session_id: u8,
        qfi: u8,
        upf_teid: u32,
        upf_ip: Ipv4Address,
    ) -> Result<N3iwfPduSession, N3iwfError> {
        let ctx = self
            .ue_contexts_by_ip
            .get_mut(&ue_untrusted_ip)
            .ok_or(N3iwfError::UeNotFound)?;

        if !ctx.authenticated {
            return Err(N3iwfError::Unauthenticated);
        }

        let n3_dl_teid = self.next_dl_teid;
        self.next_dl_teid += 1;

        let spi_in = self.next_spi;
        self.next_spi += 1;
        let spi_out = self.next_spi;
        self.next_spi += 1;

        let k_n3iwf = ctx.k_n3iwf.unwrap_or([0u8; 32]);
        let mut k_enc = [0u8; 16];
        let mut k_int = [0u8; 16];
        k_enc.copy_from_slice(&k_n3iwf[0..16]);
        k_int.copy_from_slice(&k_n3iwf[16..32]);

        let child_sa = N3iwfChildSa {
            spi_in,
            spi_out,
            pdu_session_id,
            qfi,
            k_enc,
            k_int,
        };

        ctx.child_sas.insert(spi_in, child_sa);
        self.spi_in_to_ue.insert(spi_in, ue_untrusted_ip);

        let pdu_session = N3iwfPduSession {
            pdu_session_id,
            qfi,
            upf_teid,
            upf_ip,
            n3_dl_teid,
            child_spi_in: spi_in,
            child_spi_out: spi_out,
        };

        ctx.pdu_sessions.insert(pdu_session_id, pdu_session.clone());
        self.dl_teid_to_ue
            .insert(n3_dl_teid, (ue_untrusted_ip, pdu_session_id));

        Ok(pdu_session)
    }

    // -----------------------------------------------------------------------
    // User Plane Bidirectional Translation (NWu ESP <-> N3 GTP-U)
    // -----------------------------------------------------------------------

    /// Uplink: Decapsulate IPsec ESP from UE over NWu -> Encapsulate into GTP-U to UPF.
    pub fn uplink_esp_to_gtpu(&self, esp: &EspPacket) -> Result<GtpuPacket, N3iwfError> {
        let ue_ip = self
            .spi_in_to_ue
            .get(&esp.spi)
            .ok_or(N3iwfError::SecurityAssociationNotFound)?;

        let ctx = self
            .ue_contexts_by_ip
            .get(ue_ip)
            .ok_or(N3iwfError::UeNotFound)?;

        let child_sa = ctx
            .child_sas
            .get(&esp.spi)
            .ok_or(N3iwfError::SecurityAssociationNotFound)?;

        // Verify ICV
        let expected_icv = compute_icv(
            &child_sa.k_int,
            esp.spi,
            esp.seq_num,
            &esp.encrypted_payload,
        );
        if !constant_time_eq_16(&expected_icv, &esp.icv) {
            return Err(N3iwfError::IntegrityCheckFailed);
        }

        // Decrypt payload
        let plaintext = xor_payload(&esp.encrypted_payload, &child_sa.k_enc, esp.seq_num);

        let pdu_session = ctx
            .pdu_sessions
            .get(&child_sa.pdu_session_id)
            .ok_or(N3iwfError::PduSessionNotFound)?;

        Ok(GtpuPacket {
            teid: pdu_session.upf_teid,
            qfi: child_sa.qfi,
            payload: plaintext,
        })
    }

    /// Downlink: Decapsulate GTP-U from UPF over N3 -> Encapsulate into IPsec ESP to UE.
    pub fn downlink_gtpu_to_esp(
        &self,
        gtpu: &GtpuPacket,
        seq_num: u32,
    ) -> Result<EspPacket, N3iwfError> {
        let (ue_ip, pdu_session_id) = self
            .dl_teid_to_ue
            .get(&gtpu.teid)
            .ok_or(N3iwfError::PduSessionNotFound)?;

        let ctx = self
            .ue_contexts_by_ip
            .get(ue_ip)
            .ok_or(N3iwfError::UeNotFound)?;

        let pdu_session = ctx
            .pdu_sessions
            .get(pdu_session_id)
            .ok_or(N3iwfError::PduSessionNotFound)?;

        let child_sa = ctx
            .child_sas
            .get(&pdu_session.child_spi_in)
            .ok_or(N3iwfError::SecurityAssociationNotFound)?;

        // Encrypt payload
        let encrypted = xor_payload(&gtpu.payload, &child_sa.k_enc, seq_num);

        // Compute ICV
        let icv = compute_icv(&child_sa.k_int, child_sa.spi_out, seq_num, &encrypted);

        Ok(EspPacket {
            spi: child_sa.spi_out,
            seq_num,
            encrypted_payload: encrypted,
            icv,
        })
    }

    /// Helper: Encapsulate and encrypt uplink payload into IPsec ESP as sent by UE.
    pub fn encrypt_uplink_esp(
        &self,
        ue_untrusted_ip: Ipv4Address,
        pdu_session_id: u8,
        seq_num: u32,
        plaintext: &[u8],
    ) -> Result<EspPacket, N3iwfError> {
        let ctx = self
            .ue_contexts_by_ip
            .get(&ue_untrusted_ip)
            .ok_or(N3iwfError::UeNotFound)?;

        let pdu_session = ctx
            .pdu_sessions
            .get(&pdu_session_id)
            .ok_or(N3iwfError::PduSessionNotFound)?;

        let child_sa = ctx
            .child_sas
            .get(&pdu_session.child_spi_in)
            .ok_or(N3iwfError::SecurityAssociationNotFound)?;

        let encrypted = xor_payload(plaintext, &child_sa.k_enc, seq_num);
        let icv = compute_icv(&child_sa.k_int, child_sa.spi_in, seq_num, &encrypted);

        Ok(EspPacket {
            spi: child_sa.spi_in,
            seq_num,
            encrypted_payload: encrypted,
            icv,
        })
    }
}

// ---------------------------------------------------------------------------
// Cryptographic Helper Functions
// ---------------------------------------------------------------------------

fn xor_payload(data: &[u8], key: &[u8; 16], seq: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let seq_bytes = seq.to_be_bytes();
    for (i, &b) in data.iter().enumerate() {
        let k = key[i % 16] ^ seq_bytes[i % 4];
        out.push(b ^ k);
    }
    out
}

fn compute_icv(key: &[u8; 16], spi: u32, seq: u32, payload: &[u8]) -> [u8; 16] {
    let mut icv = [0u8; 16];
    icv.copy_from_slice(key);
    let spi_bytes = spi.to_be_bytes();
    let seq_bytes = seq.to_be_bytes();

    for (i, &b) in payload.iter().enumerate() {
        let idx = (i + (seq as usize)) % 16;
        icv[idx] = icv[idx].wrapping_add(b).rotate_left(2);
    }
    for i in 0..4 {
        icv[i] ^= spi_bytes[i];
        icv[i + 4] ^= seq_bytes[i];
    }
    icv
}

fn constant_time_eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

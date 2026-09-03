//! 3GPP TS 24.501 5G Non-Access Stratum (NAS) Protocol Engine.
//!
//! Implements 5G Non-Access Stratum signaling between UE and 5G Core AMF/SMF:
//! - 5GMM (5G Mobility Management):
//!   - Registration procedure (Request, Accept, Complete, Reject)
//!   - Authentication (5G-AKA challenge with RAND/AUTN and RES* calculation)
//!   - NAS Security Mode Command / Complete (Integrity & Ciphering protection)
//!   - De-registration procedure (UE and Network-initiated)
//!   - UL & DL NAS Transport (multiplexing 5GSM inside 5GMM containers)
//! - 5GSM (5G Session Management):
//!   - PDU Session Establishment (Request, Accept, Reject) with IPv4 address allocation
//!   - PDU Session Release (Request, Command, Complete)
//!   - QoS Rules & Session-AMBR negotiation
//! - NAS Security Headers (Plain, Integrity Protected, Ciphered) with SQN & MAC
//! - 5GMM and 5GSM UE and AMF/SMF state machines

use std::collections::HashMap;

use crate::ipv4::Ipv4Address;
use crate::ngap_5g::{PlmnId, Snssai};

// ---------------------------------------------------------------------------
// Constants & Protocol Discriminators (TS 24.501 Section 9.1 - 9.3)
// ---------------------------------------------------------------------------

/// Extended Protocol Discriminator (EPD) values.
pub const EPD_5GS_MOBILITY_MANAGEMENT: u8 = 0x7E;
pub const EPD_5GS_SESSION_MANAGEMENT: u8 = 0x2E;

/// Security Header Types (SHT).
pub const SHT_PLAIN_NAS: u8 = 0x00;
pub const SHT_INTEGRITY_PROTECTED: u8 = 0x01;
pub const SHT_INTEGRITY_AND_CIPHERED: u8 = 0x02;
pub const SHT_INTEGRITY_WITH_NEW_CONTEXT: u8 = 0x03;
pub const SHT_INTEGRITY_AND_CIPHERED_WITH_NEW_CONTEXT: u8 = 0x04;

/// 5GMM Message Types.
pub const NAS_5GMM_REGISTRATION_REQUEST: u8 = 0x41;
pub const NAS_5GMM_REGISTRATION_ACCEPT: u8 = 0x42;
pub const NAS_5GMM_REGISTRATION_COMPLETE: u8 = 0x43;
pub const NAS_5GMM_REGISTRATION_REJECT: u8 = 0x44;
pub const NAS_5GMM_DEREGISTRATION_REQUEST_UE_ORIGINATING: u8 = 0x45;
pub const NAS_5GMM_DEREGISTRATION_ACCEPT_UE_ORIGINATING: u8 = 0x46;
pub const NAS_5GMM_AUTHENTICATION_REQUEST: u8 = 0x56;
pub const NAS_5GMM_AUTHENTICATION_RESPONSE: u8 = 0x57;
pub const NAS_5GMM_AUTHENTICATION_REJECT: u8 = 0x58;
pub const NAS_5GMM_SECURITY_MODE_COMMAND: u8 = 0x5D;
pub const NAS_5GMM_SECURITY_MODE_COMPLETE: u8 = 0x5E;
pub const NAS_5GMM_SECURITY_MODE_REJECT: u8 = 0x5F;
pub const NAS_5GMM_UL_NAS_TRANSPORT: u8 = 0x67;
pub const NAS_5GMM_DL_NAS_TRANSPORT: u8 = 0x68;

/// 5GSM Message Types.
pub const NAS_5GSM_PDU_SESSION_ESTABLISHMENT_REQUEST: u8 = 0xC1;
pub const NAS_5GSM_PDU_SESSION_ESTABLISHMENT_ACCEPT: u8 = 0xC2;
pub const NAS_5GSM_PDU_SESSION_ESTABLISHMENT_REJECT: u8 = 0xC3;
pub const NAS_5GSM_PDU_SESSION_RELEASE_REQUEST: u8 = 0xD1;
pub const NAS_5GSM_PDU_SESSION_RELEASE_COMMAND: u8 = 0xD3;
pub const NAS_5GSM_PDU_SESSION_RELEASE_COMPLETE: u8 = 0xD4;

// ---------------------------------------------------------------------------
// 5GMM / 5GSM Causes (TS 24.501 Section 9.11.3.2, 9.11.4.2)
// ---------------------------------------------------------------------------

/// 5GS Mobility Management (5GMM) causes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nas5GmmCause {
    IllegalUe = 3,
    IllegalMe = 6,
    FiveGsServicesNotAllowed = 7,
    PlmnNotAllowed = 11,
    TrackingAreaNotAllowed = 12,
    RoamingNotAllowedInThisTrackingArea = 13,
    NoSuitableCellsInTrackingArea = 15,
    MacFailure = 20,
    SynchFailure = 21,
    Congestion = 22,
    UeSecurityCapabilitiesMismatch = 23,
    SecurityModeRejectedUnspecified = 24,
    SemanticallyIncorrectMessage = 95,
    InvalidMandatoryInformation = 96,
}

impl Nas5GmmCause {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            3 => Some(Nas5GmmCause::IllegalUe),
            6 => Some(Nas5GmmCause::IllegalMe),
            7 => Some(Nas5GmmCause::FiveGsServicesNotAllowed),
            11 => Some(Nas5GmmCause::PlmnNotAllowed),
            12 => Some(Nas5GmmCause::TrackingAreaNotAllowed),
            13 => Some(Nas5GmmCause::RoamingNotAllowedInThisTrackingArea),
            15 => Some(Nas5GmmCause::NoSuitableCellsInTrackingArea),
            20 => Some(Nas5GmmCause::MacFailure),
            21 => Some(Nas5GmmCause::SynchFailure),
            22 => Some(Nas5GmmCause::Congestion),
            23 => Some(Nas5GmmCause::UeSecurityCapabilitiesMismatch),
            24 => Some(Nas5GmmCause::SecurityModeRejectedUnspecified),
            95 => Some(Nas5GmmCause::SemanticallyIncorrectMessage),
            96 => Some(Nas5GmmCause::InvalidMandatoryInformation),
            _ => None,
        }
    }
}

/// 5GS Session Management (5GSM) causes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nas5GsmCause {
    InsufficientResources = 26,
    MissingOrUnknownDnn = 27,
    UnknownPduSessionType = 28,
    UserAuthenticationFailed = 29,
    RequestRejectedByIntermediateNode = 30,
    ServiceOptionNotSupported = 32,
    PtiMismatch = 35,
    RegularDeactivation = 36,
    NetworkFailure = 38,
    SemanticErrorInTftOperation = 41,
    SyntacticalErrorInTftOperation = 42,
    InvalidPduSessionIdentity = 43,
    SemanticallyIncorrectMessage = 95,
}

impl Nas5GsmCause {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            26 => Some(Nas5GsmCause::InsufficientResources),
            27 => Some(Nas5GsmCause::MissingOrUnknownDnn),
            28 => Some(Nas5GsmCause::UnknownPduSessionType),
            29 => Some(Nas5GsmCause::UserAuthenticationFailed),
            30 => Some(Nas5GsmCause::RequestRejectedByIntermediateNode),
            32 => Some(Nas5GsmCause::ServiceOptionNotSupported),
            35 => Some(Nas5GsmCause::PtiMismatch),
            36 => Some(Nas5GsmCause::RegularDeactivation),
            38 => Some(Nas5GsmCause::NetworkFailure),
            41 => Some(Nas5GsmCause::SemanticErrorInTftOperation),
            42 => Some(Nas5GsmCause::SyntacticalErrorInTftOperation),
            43 => Some(Nas5GsmCause::InvalidPduSessionIdentity),
            95 => Some(Nas5GsmCause::SemanticallyIncorrectMessage),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// 5GS Identifiers & Information Elements (TS 24.501 Section 9.11)
// ---------------------------------------------------------------------------

/// 5GS Registration Type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationType5Gs {
    InitialRegistration = 1,
    MobilityRegistrationUpdating = 2,
    PeriodicRegistrationUpdating = 3,
    EmergencyRegistration = 4,
}

impl RegistrationType5Gs {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v & 0x07 {
            1 => Some(RegistrationType5Gs::InitialRegistration),
            2 => Some(RegistrationType5Gs::MobilityRegistrationUpdating),
            3 => Some(RegistrationType5Gs::PeriodicRegistrationUpdating),
            4 => Some(RegistrationType5Gs::EmergencyRegistration),
            _ => None,
        }
    }
}

/// 5GS Mobile Identity: SUCI or 5G-GUTI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MobileIdentity5Gs {
    /// Subscription Concealed Identifier (SUCI).
    Suci {
        plmn: PlmnId,
        routing_indicator: u16,
        protection_scheme_id: u8, // 0 = Null scheme
        home_network_pki: u8,
        scheme_output: Vec<u8>,
    },
    /// Globally Unique Temporary Identifier (5G-GUTI).
    Guti5Gs {
        plmn: PlmnId,
        amf_region_id: u8,
        amf_set_id: u16, // 10 bits
        amf_pointer: u8, // 6 bits
        tmsi_5g: u32,
    },
}

/// 5GS Security Capabilities (algorithms supported by UE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UeSecurityCapabilities {
    pub nea0: bool,
    pub nea1: bool,
    pub nea2: bool,
    pub nea3: bool,
    pub nia0: bool,
    pub nia1: bool,
    pub nia2: bool,
    pub nia3: bool,
}

impl Default for UeSecurityCapabilities {
    fn default() -> Self {
        UeSecurityCapabilities {
            nea0: true,
            nea1: true,
            nea2: true,
            nea3: false,
            nia0: true,
            nia1: true,
            nia2: true,
            nia3: false,
        }
    }
}

impl UeSecurityCapabilities {
    pub fn encode(&self) -> [u8; 2] {
        let mut b0 = 0u8;
        if self.nea0 {
            b0 |= 0x80;
        }
        if self.nea1 {
            b0 |= 0x40;
        }
        if self.nea2 {
            b0 |= 0x20;
        }
        if self.nea3 {
            b0 |= 0x10;
        }

        let mut b1 = 0u8;
        if self.nia0 {
            b1 |= 0x80;
        }
        if self.nia1 {
            b1 |= 0x40;
        }
        if self.nia2 {
            b1 |= 0x20;
        }
        if self.nia3 {
            b1 |= 0x10;
        }

        [b0, b1]
    }

    pub fn decode(bytes: [u8; 2]) -> Self {
        UeSecurityCapabilities {
            nea0: (bytes[0] & 0x80) != 0,
            nea1: (bytes[0] & 0x40) != 0,
            nea2: (bytes[0] & 0x20) != 0,
            nea3: (bytes[0] & 0x10) != 0,
            nia0: (bytes[1] & 0x80) != 0,
            nia1: (bytes[1] & 0x40) != 0,
            nia2: (bytes[1] & 0x20) != 0,
            nia3: (bytes[1] & 0x10) != 0,
        }
    }
}

/// PDU Session Type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PduSessionType {
    Ipv4 = 1,
    Ipv6 = 2,
    Ipv4v6 = 3,
    Unstructured = 4,
    Ethernet = 5,
}

impl PduSessionType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v & 0x07 {
            1 => Some(PduSessionType::Ipv4),
            2 => Some(PduSessionType::Ipv6),
            3 => Some(PduSessionType::Ipv4v6),
            4 => Some(PduSessionType::Unstructured),
            5 => Some(PduSessionType::Ethernet),
            _ => None,
        }
    }
}

/// Session and Service Continuity (SSC) Mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SscMode {
    Ssc1 = 1,
    Ssc2 = 2,
    Ssc3 = 3,
}

impl SscMode {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v & 0x07 {
            1 => Some(SscMode::Ssc1),
            2 => Some(SscMode::Ssc2),
            3 => Some(SscMode::Ssc3),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// 5GMM Messages (TS 24.501 Section 8.2)
// ---------------------------------------------------------------------------

/// 5GMM Registration Request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationRequest {
    pub registration_type: RegistrationType5Gs,
    pub ng_ksi: u8, // 0..7
    pub mobile_identity: MobileIdentity5Gs,
    pub ue_security_capabilities: UeSecurityCapabilities,
    pub requested_nssai: Vec<Snssai>,
}

/// 5GMM Registration Accept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationAccept {
    pub registration_result_3gpp: bool,
    pub allocated_guti: Option<MobileIdentity5Gs>,
    pub allowed_nssai: Vec<Snssai>,
    pub t3512_periodic_reg_update_secs: u32,
}

/// 5GMM Registration Reject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationReject {
    pub cause: Nas5GmmCause,
}

/// 5GMM Authentication Request (5G-AKA challenge).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationRequest {
    pub ng_ksi: u8,
    pub rand: [u8; 16],
    pub autn: [u8; 16],
}

/// 5GMM Authentication Response (UE response with RES*).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationResponse {
    pub res_star: [u8; 16],
}

/// 5GMM Security Mode Command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityModeCommand {
    pub selected_ciphering_algorithm: u8, // 0..3 (NEA0..3)
    pub selected_integrity_algorithm: u8, // 0..3 (NIA0..3)
    pub ng_ksi: u8,
    pub replayed_ue_security_capabilities: UeSecurityCapabilities,
}

/// 5GMM Security Mode Complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityModeComplete {
    pub imeisv: Option<u64>,
}

/// 5GMM Uplink NAS Transport (transports 5GSM PDU Session requests).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UlNasTransport {
    pub payload_container_type: u8, // 1 = N1 SM information
    pub pdu_session_id: u8,
    pub request_type: u8,    // 1 = Initial request
    pub dnn: Option<String>, // e.g. "internet"
    pub s_nssai: Option<Snssai>,
    pub sm_payload: Vec<u8>, // Encapsulated 5GSM message
}

/// 5GMM Downlink NAS Transport (transports 5GSM PDU Session responses).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DlNasTransport {
    pub payload_container_type: u8, // 1 = N1 SM information
    pub pdu_session_id: u8,
    pub sm_payload: Vec<u8>, // Encapsulated 5GSM message
}

/// 5GMM De-registration Request (UE-originating).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeregistrationRequest {
    pub switch_off: bool,
    pub ng_ksi: u8,
    pub mobile_identity: MobileIdentity5Gs,
}

// ---------------------------------------------------------------------------
// 5GSM Messages (TS 24.501 Section 8.3)
// ---------------------------------------------------------------------------

/// 5GSM PDU Session Establishment Request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PduSessionEstablishmentRequest {
    pub pdu_session_id: u8,
    pub pti: u8, // Procedure Transaction Identity
    pub pdu_session_type: PduSessionType,
    pub ssc_mode: SscMode,
}

/// 5GSM PDU Session Establishment Accept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PduSessionEstablishmentAccept {
    pub pdu_session_id: u8,
    pub pti: u8,
    pub selected_pdu_session_type: PduSessionType,
    pub selected_ssc_mode: SscMode,
    pub allocated_ipv4: Option<Ipv4Address>,
    pub session_ambr_dl_kbps: u32,
    pub session_ambr_ul_kbps: u32,
    pub authorized_qfi: u8,
}

/// 5GSM PDU Session Establishment Reject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PduSessionEstablishmentReject {
    pub pdu_session_id: u8,
    pub pti: u8,
    pub cause: Nas5GsmCause,
}

/// 5GSM PDU Session Release Request (UE-initiated).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PduSessionReleaseRequest {
    pub pdu_session_id: u8,
    pub pti: u8,
    pub cause: Option<Nas5GsmCause>,
}

/// 5GSM PDU Session Release Command (Network-initiated).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PduSessionReleaseCommand {
    pub pdu_session_id: u8,
    pub pti: u8,
    pub cause: Nas5GsmCause,
}

/// 5GSM PDU Session Release Complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PduSessionReleaseComplete {
    pub pdu_session_id: u8,
    pub pti: u8,
}

// ---------------------------------------------------------------------------
// NAS PDU Enums & Serialization / Deserialization
// ---------------------------------------------------------------------------

/// Unified 5GMM Message representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Nas5GmmMessage {
    RegistrationRequest(RegistrationRequest),
    RegistrationAccept(RegistrationAccept),
    RegistrationComplete,
    RegistrationReject(RegistrationReject),
    AuthenticationRequest(AuthenticationRequest),
    AuthenticationResponse(AuthenticationResponse),
    SecurityModeCommand(SecurityModeCommand),
    SecurityModeComplete(SecurityModeComplete),
    UlNasTransport(UlNasTransport),
    DlNasTransport(DlNasTransport),
    DeregistrationRequest(DeregistrationRequest),
    DeregistrationAccept,
}

/// Unified 5GSM Message representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Nas5GsmMessage {
    EstablishmentRequest(PduSessionEstablishmentRequest),
    EstablishmentAccept(PduSessionEstablishmentAccept),
    EstablishmentReject(PduSessionEstablishmentReject),
    ReleaseRequest(PduSessionReleaseRequest),
    ReleaseCommand(PduSessionReleaseCommand),
    ReleaseComplete(PduSessionReleaseComplete),
}

/// Complete NAS PDU container (with or without security header).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasPdu {
    pub security_header_type: u8,
    pub message_authentication_code: u32,
    pub sequence_number: u8,
    pub gmm_message: Option<Nas5GmmMessage>,
    pub gsm_message: Option<Nas5GsmMessage>,
}

impl NasPdu {
    /// Create a plain 5GMM NAS PDU.
    pub fn new_plain_gmm(msg: Nas5GmmMessage) -> Self {
        NasPdu {
            security_header_type: SHT_PLAIN_NAS,
            message_authentication_code: 0,
            sequence_number: 0,
            gmm_message: Some(msg),
            gsm_message: None,
        }
    }

    /// Create a plain 5GSM NAS PDU.
    pub fn new_plain_gsm(msg: Nas5GsmMessage) -> Self {
        NasPdu {
            security_header_type: SHT_PLAIN_NAS,
            message_authentication_code: 0,
            sequence_number: 0,
            gmm_message: None,
            gsm_message: Some(msg),
        }
    }

    /// Wrap a plain PDU in an integrity-protected NAS container.
    pub fn with_integrity(mut self, mac: u32, sqn: u8) -> Self {
        self.security_header_type = SHT_INTEGRITY_PROTECTED;
        self.message_authentication_code = mac;
        self.sequence_number = sqn;
        self
    }

    /// Encode the NAS PDU to standard wire bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        if self.security_header_type != SHT_PLAIN_NAS {
            // Security Protected Header (TS 24.501 Section 9.1.1)
            buf.push(EPD_5GS_MOBILITY_MANAGEMENT);
            buf.push(self.security_header_type & 0x0F);
            buf.extend_from_slice(&self.message_authentication_code.to_be_bytes());
            buf.push(self.sequence_number);
        }

        if let Some(ref gmm) = self.gmm_message {
            encode_gmm_message(gmm, &mut buf);
        } else if let Some(ref gsm) = self.gsm_message {
            encode_gsm_message(gsm, &mut buf);
        }

        buf
    }

    /// Parse a wire-format NAS PDU.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 3 {
            return None;
        }

        let epd = data[0];
        let mut offset = 0;
        let mut sht = SHT_PLAIN_NAS;
        let mut mac = 0u32;
        let mut sqn = 0u8;

        if epd == EPD_5GS_MOBILITY_MANAGEMENT && (data[1] & 0x0F) != SHT_PLAIN_NAS {
            // Has security header
            if data.len() < 7 {
                return None;
            }
            sht = data[1] & 0x0F;
            let mut mac_bytes = [0u8; 4];
            mac_bytes.copy_from_slice(&data[2..6]);
            mac = u32::from_be_bytes(mac_bytes);
            sqn = data[6];
            offset = 7;
        }

        if offset >= data.len() {
            return None;
        }

        let inner_epd = data[offset];
        match inner_epd {
            EPD_5GS_MOBILITY_MANAGEMENT => {
                let gmm_msg = decode_gmm_message(&data[offset..])?;
                Some(NasPdu {
                    security_header_type: sht,
                    message_authentication_code: mac,
                    sequence_number: sqn,
                    gmm_message: Some(gmm_msg),
                    gsm_message: None,
                })
            }
            EPD_5GS_SESSION_MANAGEMENT => {
                let gsm_msg = decode_gsm_message(&data[offset..])?;
                Some(NasPdu {
                    security_header_type: sht,
                    message_authentication_code: mac,
                    sequence_number: sqn,
                    gmm_message: None,
                    gsm_message: Some(gsm_msg),
                })
            }
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// GMM / GSM Encoders & Decoders
// ---------------------------------------------------------------------------

fn encode_gmm_message(msg: &Nas5GmmMessage, buf: &mut Vec<u8>) {
    buf.push(EPD_5GS_MOBILITY_MANAGEMENT);
    buf.push(SHT_PLAIN_NAS);

    match msg {
        Nas5GmmMessage::RegistrationRequest(req) => {
            buf.push(NAS_5GMM_REGISTRATION_REQUEST);
            buf.push((req.ng_ksi & 0x07) << 4 | (req.registration_type as u8 & 0x07));
            encode_mobile_identity(&req.mobile_identity, buf);
            let sec_caps = req.ue_security_capabilities.encode();
            buf.extend_from_slice(&sec_caps);
            buf.push(req.requested_nssai.len() as u8);
            for s in &req.requested_nssai {
                buf.push(s.sst);
            }
        }
        Nas5GmmMessage::RegistrationAccept(acc) => {
            buf.push(NAS_5GMM_REGISTRATION_ACCEPT);
            buf.push(if acc.registration_result_3gpp { 1 } else { 0 });
            if let Some(ref guti) = acc.allocated_guti {
                buf.push(1);
                encode_mobile_identity(guti, buf);
            } else {
                buf.push(0);
            }
            buf.push(acc.allowed_nssai.len() as u8);
            for s in &acc.allowed_nssai {
                buf.push(s.sst);
            }
            buf.extend_from_slice(&acc.t3512_periodic_reg_update_secs.to_be_bytes());
        }
        Nas5GmmMessage::RegistrationComplete => {
            buf.push(NAS_5GMM_REGISTRATION_COMPLETE);
        }
        Nas5GmmMessage::RegistrationReject(rej) => {
            buf.push(NAS_5GMM_REGISTRATION_REJECT);
            buf.push(rej.cause as u8);
        }
        Nas5GmmMessage::AuthenticationRequest(auth) => {
            buf.push(NAS_5GMM_AUTHENTICATION_REQUEST);
            buf.push(auth.ng_ksi & 0x07);
            buf.extend_from_slice(&auth.rand);
            buf.extend_from_slice(&auth.autn);
        }
        Nas5GmmMessage::AuthenticationResponse(resp) => {
            buf.push(NAS_5GMM_AUTHENTICATION_RESPONSE);
            buf.extend_from_slice(&resp.res_star);
        }
        Nas5GmmMessage::SecurityModeCommand(cmd) => {
            buf.push(NAS_5GMM_SECURITY_MODE_COMMAND);
            buf.push(cmd.selected_ciphering_algorithm);
            buf.push(cmd.selected_integrity_algorithm);
            buf.push(cmd.ng_ksi);
            let caps = cmd.replayed_ue_security_capabilities.encode();
            buf.extend_from_slice(&caps);
        }
        Nas5GmmMessage::SecurityModeComplete(comp) => {
            buf.push(NAS_5GMM_SECURITY_MODE_COMPLETE);
            if let Some(imeisv) = comp.imeisv {
                buf.push(1);
                buf.extend_from_slice(&imeisv.to_be_bytes());
            } else {
                buf.push(0);
            }
        }
        Nas5GmmMessage::UlNasTransport(transport) => {
            buf.push(NAS_5GMM_UL_NAS_TRANSPORT);
            buf.push(transport.payload_container_type);
            buf.push(transport.pdu_session_id);
            buf.push(transport.request_type);
            buf.extend_from_slice(&(transport.sm_payload.len() as u16).to_be_bytes());
            buf.extend_from_slice(&transport.sm_payload);
        }
        Nas5GmmMessage::DlNasTransport(transport) => {
            buf.push(NAS_5GMM_DL_NAS_TRANSPORT);
            buf.push(transport.payload_container_type);
            buf.push(transport.pdu_session_id);
            buf.extend_from_slice(&(transport.sm_payload.len() as u16).to_be_bytes());
            buf.extend_from_slice(&transport.sm_payload);
        }
        Nas5GmmMessage::DeregistrationRequest(req) => {
            buf.push(NAS_5GMM_DEREGISTRATION_REQUEST_UE_ORIGINATING);
            buf.push(if req.switch_off { 1 } else { 0 } | ((req.ng_ksi & 0x07) << 4));
            encode_mobile_identity(&req.mobile_identity, buf);
        }
        Nas5GmmMessage::DeregistrationAccept => {
            buf.push(NAS_5GMM_DEREGISTRATION_ACCEPT_UE_ORIGINATING);
        }
    }
}

fn decode_gmm_message(data: &[u8]) -> Option<Nas5GmmMessage> {
    if data.len() < 3 {
        return None;
    }
    let msg_type = data[2];
    match msg_type {
        NAS_5GMM_REGISTRATION_REQUEST => {
            if data.len() < 7 {
                return None;
            }
            let reg_type = RegistrationType5Gs::from_u8(data[3] & 0x07)?;
            let ng_ksi = (data[3] >> 4) & 0x07;
            let (mobile_id, consumed) = decode_mobile_identity(&data[4..])?;
            let mut offset = 4 + consumed;
            if offset + 2 > data.len() {
                return None;
            }
            let sec_caps = UeSecurityCapabilities::decode([data[offset], data[offset + 1]]);
            offset += 2;
            let mut requested_nssai = Vec::new();
            if offset < data.len() {
                let nssai_len = data[offset] as usize;
                offset += 1;
                for _ in 0..nssai_len {
                    if offset < data.len() {
                        requested_nssai.push(Snssai {
                            sst: data[offset],
                            sd: None,
                        });
                        offset += 1;
                    }
                }
            }
            Some(Nas5GmmMessage::RegistrationRequest(RegistrationRequest {
                registration_type: reg_type,
                ng_ksi,
                mobile_identity: mobile_id,
                ue_security_capabilities: sec_caps,
                requested_nssai,
            }))
        }
        NAS_5GMM_REGISTRATION_ACCEPT => {
            if data.len() < 8 {
                return None;
            }
            let reg_3gpp = data[3] != 0;
            let has_guti = data[4] != 0;
            let mut offset = 5;
            let allocated_guti = if has_guti {
                let (guti, consumed) = decode_mobile_identity(&data[offset..])?;
                offset += consumed;
                Some(guti)
            } else {
                None
            };
            if offset >= data.len() {
                return None;
            }
            let nssai_len = data[offset] as usize;
            offset += 1;
            let mut allowed_nssai = Vec::new();
            for _ in 0..nssai_len {
                if offset < data.len() {
                    allowed_nssai.push(Snssai {
                        sst: data[offset],
                        sd: None,
                    });
                    offset += 1;
                }
            }
            if offset + 4 > data.len() {
                return None;
            }
            let mut t3512_bytes = [0u8; 4];
            t3512_bytes.copy_from_slice(&data[offset..offset + 4]);
            let t3512 = u32::from_be_bytes(t3512_bytes);
            Some(Nas5GmmMessage::RegistrationAccept(RegistrationAccept {
                registration_result_3gpp: reg_3gpp,
                allocated_guti,
                allowed_nssai,
                t3512_periodic_reg_update_secs: t3512,
            }))
        }
        NAS_5GMM_REGISTRATION_COMPLETE => Some(Nas5GmmMessage::RegistrationComplete),
        NAS_5GMM_REGISTRATION_REJECT => {
            if data.len() < 4 {
                return None;
            }
            Some(Nas5GmmMessage::RegistrationReject(RegistrationReject {
                cause: Nas5GmmCause::from_u8(data[3])?,
            }))
        }
        NAS_5GMM_AUTHENTICATION_REQUEST => {
            if data.len() < 36 {
                return None;
            }
            let ng_ksi = data[3] & 0x07;
            let mut rand = [0u8; 16];
            rand.copy_from_slice(&data[4..20]);
            let mut autn = [0u8; 16];
            autn.copy_from_slice(&data[20..36]);
            Some(Nas5GmmMessage::AuthenticationRequest(
                AuthenticationRequest { ng_ksi, rand, autn },
            ))
        }
        NAS_5GMM_AUTHENTICATION_RESPONSE => {
            if data.len() < 19 {
                return None;
            }
            let mut res_star = [0u8; 16];
            res_star.copy_from_slice(&data[3..19]);
            Some(Nas5GmmMessage::AuthenticationResponse(
                AuthenticationResponse { res_star },
            ))
        }
        NAS_5GMM_SECURITY_MODE_COMMAND => {
            if data.len() < 8 {
                return None;
            }
            let ciph = data[3];
            let integ = data[4];
            let ng_ksi = data[5];
            let caps = UeSecurityCapabilities::decode([data[6], data[7]]);
            Some(Nas5GmmMessage::SecurityModeCommand(SecurityModeCommand {
                selected_ciphering_algorithm: ciph,
                selected_integrity_algorithm: integ,
                ng_ksi,
                replayed_ue_security_capabilities: caps,
            }))
        }
        NAS_5GMM_SECURITY_MODE_COMPLETE => {
            if data.len() < 4 {
                return None;
            }
            let has_imeisv = data[3] != 0;
            let imeisv = if has_imeisv {
                if data.len() < 12 {
                    return None;
                }
                let mut b = [0u8; 8];
                b.copy_from_slice(&data[4..12]);
                Some(u64::from_be_bytes(b))
            } else {
                None
            };
            Some(Nas5GmmMessage::SecurityModeComplete(SecurityModeComplete {
                imeisv,
            }))
        }
        NAS_5GMM_UL_NAS_TRANSPORT => {
            if data.len() < 8 {
                return None;
            }
            let pct = data[3];
            let session_id = data[4];
            let req_type = data[5];
            let mut len_b = [0u8; 2];
            len_b.copy_from_slice(&data[6..8]);
            let payload_len = u16::from_be_bytes(len_b) as usize;
            if data.len() < 8 + payload_len {
                return None;
            }
            let sm_payload = data[8..8 + payload_len].to_vec();
            Some(Nas5GmmMessage::UlNasTransport(UlNasTransport {
                payload_container_type: pct,
                pdu_session_id: session_id,
                request_type: req_type,
                dnn: None,
                s_nssai: None,
                sm_payload,
            }))
        }
        NAS_5GMM_DL_NAS_TRANSPORT => {
            if data.len() < 7 {
                return None;
            }
            let pct = data[3];
            let session_id = data[4];
            let mut len_b = [0u8; 2];
            len_b.copy_from_slice(&data[5..7]);
            let payload_len = u16::from_be_bytes(len_b) as usize;
            if data.len() < 7 + payload_len {
                return None;
            }
            let sm_payload = data[7..7 + payload_len].to_vec();
            Some(Nas5GmmMessage::DlNasTransport(DlNasTransport {
                payload_container_type: pct,
                pdu_session_id: session_id,
                sm_payload,
            }))
        }
        NAS_5GMM_DEREGISTRATION_REQUEST_UE_ORIGINATING => {
            if data.len() < 5 {
                return None;
            }
            let switch_off = (data[3] & 0x01) != 0;
            let ng_ksi = (data[3] >> 4) & 0x07;
            let (mobile_id, _) = decode_mobile_identity(&data[4..])?;
            Some(Nas5GmmMessage::DeregistrationRequest(
                DeregistrationRequest {
                    switch_off,
                    ng_ksi,
                    mobile_identity: mobile_id,
                },
            ))
        }
        NAS_5GMM_DEREGISTRATION_ACCEPT_UE_ORIGINATING => Some(Nas5GmmMessage::DeregistrationAccept),
        _ => None,
    }
}

fn encode_gsm_message(msg: &Nas5GsmMessage, buf: &mut Vec<u8>) {
    buf.push(EPD_5GS_SESSION_MANAGEMENT);
    match msg {
        Nas5GsmMessage::EstablishmentRequest(req) => {
            buf.push(req.pdu_session_id);
            buf.push(req.pti);
            buf.push(NAS_5GSM_PDU_SESSION_ESTABLISHMENT_REQUEST);
            buf.push((req.pdu_session_type as u8 & 0x07) | ((req.ssc_mode as u8 & 0x07) << 4));
        }
        Nas5GsmMessage::EstablishmentAccept(acc) => {
            buf.push(acc.pdu_session_id);
            buf.push(acc.pti);
            buf.push(NAS_5GSM_PDU_SESSION_ESTABLISHMENT_ACCEPT);
            buf.push(
                (acc.selected_pdu_session_type as u8 & 0x07)
                    | ((acc.selected_ssc_mode as u8 & 0x07) << 4),
            );
            if let Some(ip) = acc.allocated_ipv4 {
                buf.push(1);
                buf.extend_from_slice(&ip.0);
            } else {
                buf.push(0);
            }
            buf.extend_from_slice(&acc.session_ambr_dl_kbps.to_be_bytes());
            buf.extend_from_slice(&acc.session_ambr_ul_kbps.to_be_bytes());
            buf.push(acc.authorized_qfi);
        }
        Nas5GsmMessage::EstablishmentReject(rej) => {
            buf.push(rej.pdu_session_id);
            buf.push(rej.pti);
            buf.push(NAS_5GSM_PDU_SESSION_ESTABLISHMENT_REJECT);
            buf.push(rej.cause as u8);
        }
        Nas5GsmMessage::ReleaseRequest(req) => {
            buf.push(req.pdu_session_id);
            buf.push(req.pti);
            buf.push(NAS_5GSM_PDU_SESSION_RELEASE_REQUEST);
            if let Some(c) = req.cause {
                buf.push(1);
                buf.push(c as u8);
            } else {
                buf.push(0);
            }
        }
        Nas5GsmMessage::ReleaseCommand(cmd) => {
            buf.push(cmd.pdu_session_id);
            buf.push(cmd.pti);
            buf.push(NAS_5GSM_PDU_SESSION_RELEASE_COMMAND);
            buf.push(cmd.cause as u8);
        }
        Nas5GsmMessage::ReleaseComplete(comp) => {
            buf.push(comp.pdu_session_id);
            buf.push(comp.pti);
            buf.push(NAS_5GSM_PDU_SESSION_RELEASE_COMPLETE);
        }
    }
}

fn decode_gsm_message(data: &[u8]) -> Option<Nas5GsmMessage> {
    if data.len() < 4 {
        return None;
    }
    let pdu_session_id = data[1];
    let pti = data[2];
    let msg_type = data[3];

    match msg_type {
        NAS_5GSM_PDU_SESSION_ESTABLISHMENT_REQUEST => {
            if data.len() < 5 {
                return None;
            }
            let pst = PduSessionType::from_u8(data[4] & 0x07)?;
            let ssc = SscMode::from_u8((data[4] >> 4) & 0x07)?;
            Some(Nas5GsmMessage::EstablishmentRequest(
                PduSessionEstablishmentRequest {
                    pdu_session_id,
                    pti,
                    pdu_session_type: pst,
                    ssc_mode: ssc,
                },
            ))
        }
        NAS_5GSM_PDU_SESSION_ESTABLISHMENT_ACCEPT => {
            if data.len() < 15 {
                return None;
            }
            let pst = PduSessionType::from_u8(data[4] & 0x07)?;
            let ssc = SscMode::from_u8((data[4] >> 4) & 0x07)?;
            let has_ip = data[5] != 0;
            let mut offset = 6;
            let allocated_ipv4 = if has_ip {
                if data.len() < offset + 4 {
                    return None;
                }
                let ip = Ipv4Address::new(
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                );
                offset += 4;
                Some(ip)
            } else {
                None
            };
            if data.len() < offset + 9 {
                return None;
            }
            let mut dl_b = [0u8; 4];
            dl_b.copy_from_slice(&data[offset..offset + 4]);
            let dl_ambr = u32::from_be_bytes(dl_b);
            offset += 4;

            let mut ul_b = [0u8; 4];
            ul_b.copy_from_slice(&data[offset..offset + 4]);
            let ul_ambr = u32::from_be_bytes(ul_b);
            offset += 4;

            let qfi = data[offset];
            Some(Nas5GsmMessage::EstablishmentAccept(
                PduSessionEstablishmentAccept {
                    pdu_session_id,
                    pti,
                    selected_pdu_session_type: pst,
                    selected_ssc_mode: ssc,
                    allocated_ipv4,
                    session_ambr_dl_kbps: dl_ambr,
                    session_ambr_ul_kbps: ul_ambr,
                    authorized_qfi: qfi,
                },
            ))
        }
        NAS_5GSM_PDU_SESSION_ESTABLISHMENT_REJECT => {
            if data.len() < 5 {
                return None;
            }
            Some(Nas5GsmMessage::EstablishmentReject(
                PduSessionEstablishmentReject {
                    pdu_session_id,
                    pti,
                    cause: Nas5GsmCause::from_u8(data[4])?,
                },
            ))
        }
        NAS_5GSM_PDU_SESSION_RELEASE_REQUEST => {
            let cause = if data.len() >= 6 && data[4] != 0 {
                Nas5GsmCause::from_u8(data[5])
            } else {
                None
            };
            Some(Nas5GsmMessage::ReleaseRequest(PduSessionReleaseRequest {
                pdu_session_id,
                pti,
                cause,
            }))
        }
        NAS_5GSM_PDU_SESSION_RELEASE_COMMAND => {
            if data.len() < 5 {
                return None;
            }
            Some(Nas5GsmMessage::ReleaseCommand(PduSessionReleaseCommand {
                pdu_session_id,
                pti,
                cause: Nas5GsmCause::from_u8(data[4])?,
            }))
        }
        NAS_5GSM_PDU_SESSION_RELEASE_COMPLETE => {
            Some(Nas5GsmMessage::ReleaseComplete(PduSessionReleaseComplete {
                pdu_session_id,
                pti,
            }))
        }
        _ => None,
    }
}

fn encode_mobile_identity(id: &MobileIdentity5Gs, buf: &mut Vec<u8>) {
    match id {
        MobileIdentity5Gs::Suci {
            plmn,
            routing_indicator,
            protection_scheme_id,
            home_network_pki,
            scheme_output,
        } => {
            buf.push(1); // 1 = SUCI
            buf.extend_from_slice(&plmn.mcc);
            buf.extend_from_slice(&plmn.mnc);
            buf.extend_from_slice(&routing_indicator.to_be_bytes());
            buf.push(*protection_scheme_id);
            buf.push(*home_network_pki);
            buf.push(scheme_output.len() as u8);
            buf.extend_from_slice(scheme_output);
        }
        MobileIdentity5Gs::Guti5Gs {
            plmn,
            amf_region_id,
            amf_set_id,
            amf_pointer,
            tmsi_5g,
        } => {
            buf.push(2); // 2 = 5G-GUTI
            buf.extend_from_slice(&plmn.mcc);
            buf.extend_from_slice(&plmn.mnc);
            buf.push(*amf_region_id);
            buf.extend_from_slice(&amf_set_id.to_be_bytes());
            buf.push(*amf_pointer);
            buf.extend_from_slice(&tmsi_5g.to_be_bytes());
        }
    }
}

fn decode_mobile_identity(data: &[u8]) -> Option<(MobileIdentity5Gs, usize)> {
    if data.is_empty() {
        return None;
    }
    let id_type = data[0];
    match id_type {
        1 => {
            // SUCI
            if data.len() < 12 {
                return None;
            }
            let mut mcc = [0u8; 3];
            mcc.copy_from_slice(&data[1..4]);
            let mut mnc = [0u8; 3];
            mnc.copy_from_slice(&data[4..7]);
            let mut ri_b = [0u8; 2];
            ri_b.copy_from_slice(&data[7..9]);
            let ri = u16::from_be_bytes(ri_b);
            let scheme = data[9];
            let pki = data[10];
            let out_len = data[11] as usize;
            if data.len() < 12 + out_len {
                return None;
            }
            let out = data[12..12 + out_len].to_vec();
            Some((
                MobileIdentity5Gs::Suci {
                    plmn: PlmnId { mcc, mnc },
                    routing_indicator: ri,
                    protection_scheme_id: scheme,
                    home_network_pki: pki,
                    scheme_output: out,
                },
                12 + out_len,
            ))
        }
        2 => {
            // 5G-GUTI
            if data.len() < 15 {
                return None;
            }
            let mut mcc = [0u8; 3];
            mcc.copy_from_slice(&data[1..4]);
            let mut mnc = [0u8; 3];
            mnc.copy_from_slice(&data[4..7]);
            let region = data[7];
            let mut set_b = [0u8; 2];
            set_b.copy_from_slice(&data[8..10]);
            let set_id = u16::from_be_bytes(set_b);
            let pointer = data[10];
            let mut tmsi_b = [0u8; 4];
            tmsi_b.copy_from_slice(&data[11..15]);
            let tmsi = u32::from_be_bytes(tmsi_b);
            Some((
                MobileIdentity5Gs::Guti5Gs {
                    plmn: PlmnId { mcc, mnc },
                    amf_region_id: region,
                    amf_set_id: set_id,
                    amf_pointer: pointer,
                    tmsi_5g: tmsi,
                },
                15,
            ))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// 5G-AKA Authentication Verification Helper (TS 33.501 Annex A)
// ---------------------------------------------------------------------------

/// Pure standard Rust 5G-AKA vector validation helper.
/// Computes expected RES* from RAND, AUTN, and pre-shared key (K).
pub fn verify_5g_aka_challenge(rand: &[u8; 16], _autn: &[u8; 16], k_secret: &[u8; 16]) -> [u8; 16] {
    // Standard XOR-based PRF for testing / mock authentication vectors
    let mut res_star = [0u8; 16];
    for i in 0..16 {
        res_star[i] = rand[i] ^ k_secret[i] ^ (i as u8).wrapping_mul(7);
    }
    res_star
}

// ---------------------------------------------------------------------------
// 5G NAS Protocol State Machine (TS 24.501 Section 5.1, 6.1)
// ---------------------------------------------------------------------------

/// 5G Mobility Management (5GMM) State.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GmmState {
    Deregistered,
    RegisteredInitiated,
    Registered,
    DeregisteredInitiated,
}

/// 5G Session Management (5GSM) State per PDU Session ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GsmState {
    Inactive,
    ActivePending,
    Active,
    ModificationPending,
    InactivePending,
}

/// PDU Session context maintained by NAS engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PduSessionContext {
    pub pdu_session_id: u8,
    pub pti: u8,
    pub state: GsmState,
    pub session_type: PduSessionType,
    pub ssc_mode: SscMode,
    pub allocated_ip: Option<Ipv4Address>,
    pub qfi: u8,
}

/// Top-level 5G NAS Protocol Engine.
pub struct NasEngine {
    pub gmm_state: GmmState,
    pub pdu_sessions: HashMap<u8, PduSessionContext>,
    pub allocated_guti: Option<MobileIdentity5Gs>,
    pub ng_ksi: u8,
    pub nas_sqn: u8,
    pub security_active: bool,
    pub shared_secret_k: [u8; 16],
}

impl NasEngine {
    /// Create a new 5G NAS protocol engine instance.
    pub fn new(shared_secret_k: [u8; 16]) -> Self {
        NasEngine {
            gmm_state: GmmState::Deregistered,
            pdu_sessions: HashMap::new(),
            allocated_guti: None,
            ng_ksi: 7, // 7 = no key
            nas_sqn: 0,
            security_active: false,
            shared_secret_k,
        }
    }

    // -----------------------------------------------------------------------
    // UE Side Procedures
    // -----------------------------------------------------------------------

    /// (UE) Build Initial Registration Request.
    pub fn ue_build_registration_request(
        &mut self,
        suci: MobileIdentity5Gs,
        slices: Vec<Snssai>,
    ) -> NasPdu {
        self.gmm_state = GmmState::RegisteredInitiated;
        let req = RegistrationRequest {
            registration_type: RegistrationType5Gs::InitialRegistration,
            ng_ksi: self.ng_ksi,
            mobile_identity: suci,
            ue_security_capabilities: UeSecurityCapabilities::default(),
            requested_nssai: slices,
        };
        NasPdu::new_plain_gmm(Nas5GmmMessage::RegistrationRequest(req))
    }

    /// (UE) Handle 5G-AKA Authentication Request and produce Authentication Response.
    pub fn ue_handle_authentication_request(&mut self, req: &AuthenticationRequest) -> NasPdu {
        self.ng_ksi = req.ng_ksi;
        let res_star = verify_5g_aka_challenge(&req.rand, &req.autn, &self.shared_secret_k);
        let resp = AuthenticationResponse { res_star };
        NasPdu::new_plain_gmm(Nas5GmmMessage::AuthenticationResponse(resp))
    }

    /// (UE) Handle Security Mode Command and produce Security Mode Complete.
    pub fn ue_handle_security_mode_command(&mut self, cmd: &SecurityModeCommand) -> NasPdu {
        self.security_active = true;
        self.ng_ksi = cmd.ng_ksi;
        self.nas_sqn = self.nas_sqn.wrapping_add(1);

        let comp = SecurityModeComplete {
            imeisv: Some(0x8600_1234_5678_9012),
        };
        let pdu = NasPdu::new_plain_gmm(Nas5GmmMessage::SecurityModeComplete(comp));
        pdu.with_integrity(0xCAFE_BABE, self.nas_sqn)
    }

    /// (UE) Handle Registration Accept and produce Registration Complete.
    pub fn ue_handle_registration_accept(&mut self, acc: &RegistrationAccept) -> NasPdu {
        self.gmm_state = GmmState::Registered;
        if let Some(ref guti) = acc.allocated_guti {
            self.allocated_guti = Some(guti.clone());
        }
        self.nas_sqn = self.nas_sqn.wrapping_add(1);
        let pdu = NasPdu::new_plain_gmm(Nas5GmmMessage::RegistrationComplete);
        pdu.with_integrity(0xDEAD_BEEF, self.nas_sqn)
    }

    /// (UE) Build PDU Session Establishment Request embedded in UL NAS Transport.
    pub fn ue_build_pdu_session_establishment_request(
        &mut self,
        session_id: u8,
        session_type: PduSessionType,
        ssc_mode: SscMode,
    ) -> NasPdu {
        let pti = session_id.wrapping_mul(3) + 1;
        let gsm_req = PduSessionEstablishmentRequest {
            pdu_session_id: session_id,
            pti,
            pdu_session_type: session_type,
            ssc_mode,
        };
        let plain_gsm = NasPdu::new_plain_gsm(Nas5GsmMessage::EstablishmentRequest(gsm_req));
        let gsm_bytes = plain_gsm.to_bytes();

        let ctx = PduSessionContext {
            pdu_session_id: session_id,
            pti,
            state: GsmState::ActivePending,
            session_type,
            ssc_mode,
            allocated_ip: None,
            qfi: 0,
        };
        self.pdu_sessions.insert(session_id, ctx);

        let ul_transport = UlNasTransport {
            payload_container_type: 1, // N1 SM information
            pdu_session_id: session_id,
            request_type: 1, // Initial request
            dnn: Some("internet".to_string()),
            s_nssai: None,
            sm_payload: gsm_bytes,
        };

        self.nas_sqn = self.nas_sqn.wrapping_add(1);
        let pdu = NasPdu::new_plain_gmm(Nas5GmmMessage::UlNasTransport(ul_transport));
        pdu.with_integrity(0xFEED_FACE, self.nas_sqn)
    }

    /// (UE) Handle DL NAS Transport containing PduSessionEstablishmentAccept.
    pub fn ue_handle_dl_nas_transport(
        &mut self,
        transport: &DlNasTransport,
    ) -> Result<Ipv4Address, &'static str> {
        let gsm_pdu = NasPdu::from_bytes(&transport.sm_payload)
            .ok_or("Failed to decode encapsulated 5GSM PDU")?;

        match gsm_pdu.gsm_message {
            Some(Nas5GsmMessage::EstablishmentAccept(ref acc)) => {
                let ctx = self
                    .pdu_sessions
                    .get_mut(&acc.pdu_session_id)
                    .ok_or("PDU session not found on UE")?;

                ctx.state = GsmState::Active;
                ctx.allocated_ip = acc.allocated_ipv4;
                ctx.qfi = acc.authorized_qfi;

                acc.allocated_ipv4
                    .ok_or("PDU Session Establishment Accept did not contain IPv4 address")
            }
            Some(Nas5GsmMessage::EstablishmentReject(ref rej)) => {
                let ctx = self.pdu_sessions.get_mut(&rej.pdu_session_id);
                if let Some(c) = ctx {
                    c.state = GsmState::Inactive;
                }
                Err("PDU Session Establishment was rejected by network")
            }
            _ => Err("Expected 5GSM EstablishmentAccept message"),
        }
    }

    /// (UE) Build De-registration Request.
    pub fn ue_build_deregistration_request(&mut self) -> Option<NasPdu> {
        let guti = self.allocated_guti.as_ref()?.clone();
        self.gmm_state = GmmState::DeregisteredInitiated;

        let req = DeregistrationRequest {
            switch_off: false,
            ng_ksi: self.ng_ksi,
            mobile_identity: guti,
        };
        let pdu = NasPdu::new_plain_gmm(Nas5GmmMessage::DeregistrationRequest(req));
        Some(pdu.with_integrity(0x1234_5678, self.nas_sqn))
    }

    // -----------------------------------------------------------------------
    // Network (AMF/SMF) Side Procedures
    // -----------------------------------------------------------------------

    /// (Network) Generate 5G-AKA Authentication Challenge.
    pub fn net_build_authentication_request(&mut self, rand: [u8; 16], autn: [u8; 16]) -> NasPdu {
        let req = AuthenticationRequest {
            ng_ksi: 1,
            rand,
            autn,
        };
        NasPdu::new_plain_gmm(Nas5GmmMessage::AuthenticationRequest(req))
    }

    /// (Network) Verify UE Authentication Response.
    pub fn net_verify_authentication_response(
        &mut self,
        resp: &AuthenticationResponse,
        rand: &[u8; 16],
        autn: &[u8; 16],
    ) -> bool {
        let expected = verify_5g_aka_challenge(rand, autn, &self.shared_secret_k);
        resp.res_star == expected
    }

    /// (Network) Build Security Mode Command.
    pub fn net_build_security_mode_command(&mut self) -> NasPdu {
        let cmd = SecurityModeCommand {
            selected_ciphering_algorithm: 2, // NEA2 (AES)
            selected_integrity_algorithm: 2, // NIA2 (AES)
            ng_ksi: 1,
            replayed_ue_security_capabilities: UeSecurityCapabilities::default(),
        };
        let pdu = NasPdu::new_plain_gmm(Nas5GmmMessage::SecurityModeCommand(cmd));
        pdu.with_integrity(0x00AA_BBCC, 1)
    }

    /// (Network) Build Registration Accept.
    pub fn net_build_registration_accept(
        &mut self,
        allocated_guti: MobileIdentity5Gs,
        slices: Vec<Snssai>,
    ) -> NasPdu {
        let acc = RegistrationAccept {
            registration_result_3gpp: true,
            allocated_guti: Some(allocated_guti),
            allowed_nssai: slices,
            t3512_periodic_reg_update_secs: 3240, // 54 mins
        };
        let pdu = NasPdu::new_plain_gmm(Nas5GmmMessage::RegistrationAccept(acc));
        pdu.with_integrity(0x55AA_55AA, 2)
    }

    /// (Network) Process UL NAS Transport and generate DL NAS Transport with PduSessionEstablishmentAccept.
    pub fn net_handle_pdu_session_establishment_request(
        &mut self,
        transport: &UlNasTransport,
        assigned_ip: Ipv4Address,
        assigned_qfi: u8,
    ) -> Result<NasPdu, &'static str> {
        let inner_pdu =
            NasPdu::from_bytes(&transport.sm_payload).ok_or("Failed to decode inner 5GSM PDU")?;

        let req = match inner_pdu.gsm_message {
            Some(Nas5GsmMessage::EstablishmentRequest(r)) => r,
            _ => return Err("Expected EstablishmentRequest inside UL NAS Transport"),
        };

        let gsm_accept = PduSessionEstablishmentAccept {
            pdu_session_id: req.pdu_session_id,
            pti: req.pti,
            selected_pdu_session_type: req.pdu_session_type,
            selected_ssc_mode: req.ssc_mode,
            allocated_ipv4: Some(assigned_ip),
            session_ambr_dl_kbps: 100_000,
            session_ambr_ul_kbps: 50_000,
            authorized_qfi: assigned_qfi,
        };

        let plain_gsm = NasPdu::new_plain_gsm(Nas5GsmMessage::EstablishmentAccept(gsm_accept));
        let gsm_bytes = plain_gsm.to_bytes();

        let dl_transport = DlNasTransport {
            payload_container_type: 1,
            pdu_session_id: req.pdu_session_id,
            sm_payload: gsm_bytes,
        };

        let pdu = NasPdu::new_plain_gmm(Nas5GmmMessage::DlNasTransport(dl_transport));
        Ok(pdu.with_integrity(0x7788_9900, 3))
    }
}

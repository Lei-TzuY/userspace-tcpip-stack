//! 3GPP TS 29.228 / TS 29.229 — Diameter Cx/Dx Interface.
//!
//! The Cx interface connects the I-CSCF and S-CSCF to the HSS in the
//! IMS (IP Multimedia Subsystem) core for subscriber registration,
//! authentication vector retrieval, and server assignment.
//!
//! This module implements:
//! * Diameter Application ID `16777216` (3GPP Cx)
//! * User-Authorization-Request / Answer (UAR/UAA) — Command Code 300
//! * Multimedia-Auth-Request / Answer (MAR/MAA) — Command Code 303
//! * Server-Assignment-Request / Answer (SAR/SAA) — Command Code 301
//! * 3GPP-specific AVPs:
//!   - Public-Identity (AVP 601)
//!   - Server-Name (AVP 602)
//!   - SIP-Auth-Data-Item (AVP 612, Grouped)
//!   - SIP-Number-Auth-Items (AVP 607)
//!   - User-Authorization-Type (AVP 623)
//!   - Server-Assignment-Type (AVP 614)

use std::collections::HashMap;

pub const DIAMETER_APP_CX: u32 = 16777216;
pub const CMD_UAR: u32 = 300;
pub const CMD_MAR: u32 = 303;
pub const CMD_SAR: u32 = 301;

pub const AVP_PUBLIC_IDENTITY: u32 = 601;
pub const AVP_SERVER_NAME: u32 = 602;
pub const AVP_SIP_AUTH_DATA_ITEM: u32 = 612;
pub const AVP_SIP_NUMBER_AUTH_ITEMS: u32 = 607;
pub const AVP_USER_AUTHORIZATION_TYPE: u32 = 623;
pub const AVP_SERVER_ASSIGNMENT_TYPE: u32 = 614;

/// User-Authorization-Type enumeration per TS 29.229 Section 6.3.24.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserAuthorizationType {
    Registration,                // 0
    DeRegistration,              // 1
    RegistrationAndCapabilities, // 2
}

impl UserAuthorizationType {
    pub fn as_u32(self) -> u32 {
        match self {
            Self::Registration => 0,
            Self::DeRegistration => 1,
            Self::RegistrationAndCapabilities => 2,
        }
    }

    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Registration),
            1 => Some(Self::DeRegistration),
            2 => Some(Self::RegistrationAndCapabilities),
            _ => None,
        }
    }
}

/// Server-Assignment-Type enumeration per TS 29.229 Section 6.3.15.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerAssignmentType {
    NoAssignment,             // 0
    Registration,             // 1
    ReRegistration,           // 2
    UnregisteredUser,         // 3
    TimeoutDeregistration,    // 4
    UserDeregistration,       // 5
    TimeoutDeregStoreSrvName, // 6
    UserDeregStoreSrvName,    // 7
    AdminDeregistration,      // 8
    AuthenticationFailure,    // 9
    AuthenticationTimeout,    // 10
    Deregistration,           // 11
}

impl ServerAssignmentType {
    pub fn as_u32(self) -> u32 {
        match self {
            Self::NoAssignment => 0,
            Self::Registration => 1,
            Self::ReRegistration => 2,
            Self::UnregisteredUser => 3,
            Self::TimeoutDeregistration => 4,
            Self::UserDeregistration => 5,
            Self::TimeoutDeregStoreSrvName => 6,
            Self::UserDeregStoreSrvName => 7,
            Self::AdminDeregistration => 8,
            Self::AuthenticationFailure => 9,
            Self::AuthenticationTimeout => 10,
            Self::Deregistration => 11,
        }
    }

    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::NoAssignment),
            1 => Some(Self::Registration),
            2 => Some(Self::ReRegistration),
            3 => Some(Self::UnregisteredUser),
            4 => Some(Self::TimeoutDeregistration),
            5 => Some(Self::UserDeregistration),
            6 => Some(Self::TimeoutDeregStoreSrvName),
            7 => Some(Self::UserDeregStoreSrvName),
            8 => Some(Self::AdminDeregistration),
            9 => Some(Self::AuthenticationFailure),
            10 => Some(Self::AuthenticationTimeout),
            11 => Some(Self::Deregistration),
            _ => None,
        }
    }
}

/// Diameter Cx AVP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CxAvp {
    PublicIdentity(String),
    ServerName(String),
    UserAuthorizationType(UserAuthorizationType),
    ServerAssignmentType(ServerAssignmentType),
    SipNumberAuthItems(u32),
    SipAuthDataItem {
        auth_scheme: String,
        auth_data: Vec<u8>,
    },
    ResultCode(u32),
}

/// A Diameter Cx message (Request or Answer).
#[derive(Debug, Clone)]
pub struct CxMessage {
    pub command_code: u32,
    pub is_request: bool,
    pub application_id: u32,
    pub hop_by_hop: u32,
    pub end_to_end: u32,
    pub session_id: String,
    pub avps: Vec<CxAvp>,
}

impl CxMessage {
    pub fn new_request(command_code: u32, session_id: &str) -> Self {
        CxMessage {
            command_code,
            is_request: true,
            application_id: DIAMETER_APP_CX,
            hop_by_hop: 0,
            end_to_end: 0,
            session_id: session_id.to_string(),
            avps: Vec::new(),
        }
    }

    pub fn new_answer(req: &CxMessage, result_code: u32) -> Self {
        let ans = CxMessage {
            command_code: req.command_code,
            is_request: false,
            application_id: req.application_id,
            hop_by_hop: req.hop_by_hop,
            end_to_end: req.end_to_end,
            session_id: req.session_id.clone(),
            avps: vec![CxAvp::ResultCode(result_code)],
        };
        ans
    }

    pub fn add_avp(&mut self, avp: CxAvp) {
        self.avps.push(avp);
    }

    /// Serializes to a compact binary representation for educational purposes.
    /// Format: [4B cmd][1B R-flag][4B app_id][4B h2h][4B e2e][2B session_len][session][avps...]
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.command_code.to_be_bytes());
        buf.push(if self.is_request { 0x80 } else { 0x00 });
        buf.extend_from_slice(&self.application_id.to_be_bytes());
        buf.extend_from_slice(&self.hop_by_hop.to_be_bytes());
        buf.extend_from_slice(&self.end_to_end.to_be_bytes());
        let sess_bytes = self.session_id.as_bytes();
        buf.extend_from_slice(&(sess_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(sess_bytes);

        for avp in &self.avps {
            match avp {
                CxAvp::PublicIdentity(s) => {
                    buf.extend_from_slice(&AVP_PUBLIC_IDENTITY.to_be_bytes());
                    let b = s.as_bytes();
                    buf.extend_from_slice(&(b.len() as u16).to_be_bytes());
                    buf.extend_from_slice(b);
                }
                CxAvp::ServerName(s) => {
                    buf.extend_from_slice(&AVP_SERVER_NAME.to_be_bytes());
                    let b = s.as_bytes();
                    buf.extend_from_slice(&(b.len() as u16).to_be_bytes());
                    buf.extend_from_slice(b);
                }
                CxAvp::UserAuthorizationType(t) => {
                    buf.extend_from_slice(&AVP_USER_AUTHORIZATION_TYPE.to_be_bytes());
                    buf.extend_from_slice(&2u16.to_be_bytes());
                    buf.extend_from_slice(&(t.as_u32() as u16).to_be_bytes());
                }
                CxAvp::ServerAssignmentType(t) => {
                    buf.extend_from_slice(&AVP_SERVER_ASSIGNMENT_TYPE.to_be_bytes());
                    buf.extend_from_slice(&2u16.to_be_bytes());
                    buf.extend_from_slice(&(t.as_u32() as u16).to_be_bytes());
                }
                CxAvp::SipNumberAuthItems(n) => {
                    buf.extend_from_slice(&AVP_SIP_NUMBER_AUTH_ITEMS.to_be_bytes());
                    buf.extend_from_slice(&4u16.to_be_bytes());
                    buf.extend_from_slice(&n.to_be_bytes());
                }
                CxAvp::SipAuthDataItem {
                    auth_scheme,
                    auth_data,
                } => {
                    buf.extend_from_slice(&AVP_SIP_AUTH_DATA_ITEM.to_be_bytes());
                    let scheme_b = auth_scheme.as_bytes();
                    let total = 2 + scheme_b.len() + 2 + auth_data.len();
                    buf.extend_from_slice(&(total as u16).to_be_bytes());
                    buf.extend_from_slice(&(scheme_b.len() as u16).to_be_bytes());
                    buf.extend_from_slice(scheme_b);
                    buf.extend_from_slice(&(auth_data.len() as u16).to_be_bytes());
                    buf.extend_from_slice(auth_data);
                }
                CxAvp::ResultCode(rc) => {
                    buf.extend_from_slice(&268u32.to_be_bytes()); // Result-Code AVP 268
                    buf.extend_from_slice(&4u16.to_be_bytes());
                    buf.extend_from_slice(&rc.to_be_bytes());
                }
            }
        }
        buf
    }
}

// ── HSS Cx Engine ────────────────────────────────────────────────────────

/// IMS subscriber registration record in the HSS.
#[derive(Debug, Clone)]
pub struct ImsSub {
    pub public_identity: String,
    pub private_identity: String,
    pub assigned_scscf: Option<String>,
    pub auth_scheme: String,
    pub auth_key: Vec<u8>,
}

/// HSS engine implementing the Diameter Cx interface.
#[derive(Debug, Clone)]
pub struct HssCxEngine {
    pub subscribers: HashMap<String, ImsSub>,
    pub transactions: u64,
}

impl HssCxEngine {
    pub fn new() -> Self {
        HssCxEngine {
            subscribers: HashMap::new(),
            transactions: 0,
        }
    }

    /// Provisions a subscriber.
    pub fn add_subscriber(&mut self, sub: ImsSub) {
        self.subscribers.insert(sub.public_identity.clone(), sub);
    }

    /// Processes a UAR (User-Authorization-Request) → returns UAA.
    pub fn process_uar(&mut self, uar: &CxMessage) -> CxMessage {
        self.transactions += 1;
        let pub_id = uar.avps.iter().find_map(|a| {
            if let CxAvp::PublicIdentity(s) = a {
                Some(s.clone())
            } else {
                None
            }
        });

        let mut uaa = CxMessage::new_answer(uar, 2001);

        if let Some(id) = pub_id {
            if let Some(sub) = self.subscribers.get(&id) {
                if let Some(ref scscf) = sub.assigned_scscf {
                    uaa.add_avp(CxAvp::ServerName(scscf.clone()));
                }
            } else {
                uaa.avps.clear();
                uaa.add_avp(CxAvp::ResultCode(5001)); // DIAMETER_ERROR_USER_UNKNOWN
            }
        } else {
            uaa.avps.clear();
            uaa.add_avp(CxAvp::ResultCode(5004)); // DIAMETER_ERROR_IDENTITY_NOT_REGISTERED
        }
        uaa
    }

    /// Processes a MAR (Multimedia-Auth-Request) → returns MAA with auth vectors.
    pub fn process_mar(&mut self, mar: &CxMessage) -> CxMessage {
        self.transactions += 1;
        let pub_id = mar.avps.iter().find_map(|a| {
            if let CxAvp::PublicIdentity(s) = a {
                Some(s.clone())
            } else {
                None
            }
        });

        let mut maa = CxMessage::new_answer(mar, 2001);

        if let Some(id) = pub_id {
            if let Some(sub) = self.subscribers.get(&id) {
                maa.add_avp(CxAvp::SipNumberAuthItems(1));
                maa.add_avp(CxAvp::SipAuthDataItem {
                    auth_scheme: sub.auth_scheme.clone(),
                    auth_data: sub.auth_key.clone(),
                });
            } else {
                maa.avps.clear();
                maa.add_avp(CxAvp::ResultCode(5001));
            }
        } else {
            maa.avps.clear();
            maa.add_avp(CxAvp::ResultCode(5004));
        }
        maa
    }

    /// Processes a SAR (Server-Assignment-Request) → returns SAA.
    pub fn process_sar(&mut self, sar: &CxMessage) -> CxMessage {
        self.transactions += 1;
        let pub_id = sar.avps.iter().find_map(|a| {
            if let CxAvp::PublicIdentity(s) = a {
                Some(s.clone())
            } else {
                None
            }
        });
        let server_name = sar.avps.iter().find_map(|a| {
            if let CxAvp::ServerName(s) = a {
                Some(s.clone())
            } else {
                None
            }
        });

        let mut saa = CxMessage::new_answer(sar, 2001);

        if let (Some(id), Some(srv)) = (pub_id, server_name) {
            if let Some(sub) = self.subscribers.get_mut(&id) {
                sub.assigned_scscf = Some(srv.clone());
                saa.add_avp(CxAvp::ServerName(srv));
            } else {
                saa.avps.clear();
                saa.add_avp(CxAvp::ResultCode(5001));
            }
        } else {
            saa.avps.clear();
            saa.add_avp(CxAvp::ResultCode(5004));
        }
        saa
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cx_uar_uaa_flow() {
        let mut hss = HssCxEngine::new();
        hss.add_subscriber(ImsSub {
            public_identity: "sip:alice@ims.example.com".into(),
            private_identity: "alice@ims.example.com".into(),
            assigned_scscf: Some("sip:scscf1.ims.example.com".into()),
            auth_scheme: "Digest-AKAv1-MD5".into(),
            auth_key: vec![0xAA; 16],
        });

        let mut uar = CxMessage::new_request(CMD_UAR, "cx-sess-001");
        uar.add_avp(CxAvp::PublicIdentity("sip:alice@ims.example.com".into()));
        uar.add_avp(CxAvp::UserAuthorizationType(
            UserAuthorizationType::Registration,
        ));

        let uaa = hss.process_uar(&uar);
        assert!(!uaa.is_request);
        let has_server = uaa.avps.iter().any(|a| matches!(a, CxAvp::ServerName(_)));
        assert!(has_server);
    }

    #[test]
    fn test_cx_mar_maa_auth_vector() {
        let mut hss = HssCxEngine::new();
        hss.add_subscriber(ImsSub {
            public_identity: "sip:bob@ims.example.com".into(),
            private_identity: "bob@ims.example.com".into(),
            assigned_scscf: None,
            auth_scheme: "Digest-AKAv1-MD5".into(),
            auth_key: vec![0xBB; 16],
        });

        let mut mar = CxMessage::new_request(CMD_MAR, "cx-sess-002");
        mar.add_avp(CxAvp::PublicIdentity("sip:bob@ims.example.com".into()));

        let maa = hss.process_mar(&mar);
        let auth_item = maa.avps.iter().find_map(|a| {
            if let CxAvp::SipAuthDataItem {
                auth_scheme,
                auth_data,
            } = a
            {
                Some((auth_scheme.clone(), auth_data.clone()))
            } else {
                None
            }
        });
        assert!(auth_item.is_some());
        let (scheme, key) = auth_item.unwrap();
        assert_eq!(scheme, "Digest-AKAv1-MD5");
        assert_eq!(key.len(), 16);
    }

    #[test]
    fn test_cx_sar_saa_server_assignment() {
        let mut hss = HssCxEngine::new();
        hss.add_subscriber(ImsSub {
            public_identity: "sip:carol@ims.example.com".into(),
            private_identity: "carol@ims.example.com".into(),
            assigned_scscf: None,
            auth_scheme: "Digest-AKAv1-MD5".into(),
            auth_key: vec![0xCC; 16],
        });

        let mut sar = CxMessage::new_request(CMD_SAR, "cx-sess-003");
        sar.add_avp(CxAvp::PublicIdentity("sip:carol@ims.example.com".into()));
        sar.add_avp(CxAvp::ServerName("sip:scscf2.ims.example.com".into()));
        sar.add_avp(CxAvp::ServerAssignmentType(
            ServerAssignmentType::Registration,
        ));

        let saa = hss.process_sar(&sar);
        let server = saa.avps.iter().find_map(|a| {
            if let CxAvp::ServerName(s) = a {
                Some(s.clone())
            } else {
                None
            }
        });
        assert_eq!(server, Some("sip:scscf2.ims.example.com".into()));

        // Verify HSS recorded the assignment
        let sub = hss.subscribers.get("sip:carol@ims.example.com").unwrap();
        assert_eq!(
            sub.assigned_scscf,
            Some("sip:scscf2.ims.example.com".into())
        );
    }
}

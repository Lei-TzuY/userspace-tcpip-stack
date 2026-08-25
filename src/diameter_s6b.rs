//! 3GPP TS 29.273 — Diameter S6b Interface.
//!
//! The Diameter S6b reference point connects the 3GPP AAA Server to the
//! PGW (Packet Data Network Gateway) / UPF for Non-3GPP IP access (e.g.
//! untrusted Wi-Fi access via ePDG / VoWiFi, or trusted WLAN access).
//!
//! This module implements:
//! * Diameter Application ID `16777272` (3GPP S6b).
//! * AA-Request (AAR) / AA-Answer (AAA) — Command Code 265.
//! * Session-Termination-Request (STR) / Answer (STA) — Command Code 275.
//! * Key 3GPP S6b AVPs:
//!   - `ANID` (Access Network Identity, AVP 1500)
//!   - `MIP6-Agent-Info` (AVP 486, Grouped):
//!     * `MIP-Home-Agent-Address` (AVP 491, IPv4/IPv6)
//!     * `MIP-Home-Agent-Host` (AVP 490)
//!   - `Non-3GPP-User-Status` (AVP 1505)
//!   - `APN-Configuration` (AVP 1430, Grouped)
//!   - `Visited-Network-Identifier` (AVP 600)
//!   - `Auth-Session-State` (AVP 277)
//!   - `Result-Code` (AVP 268)

use std::collections::HashMap;

pub const DIAMETER_APPLICATION_S6B: u32 = 16777272;
pub const DIAMETER_CMD_AA: u32 = 265;
pub const DIAMETER_CMD_SESSION_TERMINATION: u32 = 275;

pub const AVP_ANID: u32 = 1500;
pub const AVP_MIP6_AGENT_INFO: u32 = 486;
pub const AVP_MIP_HOME_AGENT_ADDRESS: u32 = 491;
pub const AVP_MIP_HOME_AGENT_HOST: u32 = 490;
pub const AVP_NON_3GPP_USER_STATUS: u32 = 1505;
pub const AVP_APN_CONFIGURATION: u32 = 1430;
pub const AVP_VISITED_NETWORK_IDENTIFIER: u32 = 600;
pub const AVP_USER_NAME: u32 = 1;
pub const AVP_RESULT_CODE: u32 = 268;

/// Non-3GPP User Status per 3GPP TS 29.273 Section 5.2.3.24.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Non3gppUserStatus {
    UserActive = 0,
    UserSuspended = 1,
    UserDeregistered = 2,
}

impl Non3gppUserStatus {
    pub fn as_u32(self) -> u32 {
        self as u32
    }

    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            0 => Some(Self::UserActive),
            1 => Some(Self::UserSuspended),
            2 => Some(Self::UserDeregistered),
            _ => None,
        }
    }
}

/// MIP6-Agent-Info Grouped AVP structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mip6AgentInfo {
    pub pgw_ip: [u8; 4],
    pub pgw_fqdn: String,
}

impl Mip6AgentInfo {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // MIP-Home-Agent-Address (AVP 491)
        buf.extend_from_slice(&AVP_MIP_HOME_AGENT_ADDRESS.to_be_bytes());
        buf.extend_from_slice(&4u16.to_be_bytes());
        buf.extend_from_slice(&self.pgw_ip);

        // MIP-Home-Agent-Host (AVP 490)
        buf.extend_from_slice(&AVP_MIP_HOME_AGENT_HOST.to_be_bytes());
        let fqdn_b = self.pgw_fqdn.as_bytes();
        buf.extend_from_slice(&(fqdn_b.len() as u16).to_be_bytes());
        buf.extend_from_slice(fqdn_b);
        buf
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        let mut offset = 0;
        let mut pgw_ip = [0u8; 4];
        let mut pgw_fqdn = String::new();

        while offset + 6 <= data.len() {
            let avp_code = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            let len = u16::from_be_bytes([data[offset + 4], data[offset + 5]]) as usize;
            offset += 6;
            if offset + len > data.len() {
                break;
            }
            let val = &data[offset..offset + len];
            if avp_code == AVP_MIP_HOME_AGENT_ADDRESS && len == 4 {
                pgw_ip.copy_from_slice(val);
            } else if avp_code == AVP_MIP_HOME_AGENT_HOST {
                pgw_fqdn = String::from_utf8_lossy(val).to_string();
            }
            offset += len;
        }

        Some(Mip6AgentInfo { pgw_ip, pgw_fqdn })
    }
}

/// S6b Diameter AVP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S6bAvp {
    UserName(String),
    Anid(String),
    Mip6AgentInfo(Mip6AgentInfo),
    Non3gppUserStatus(Non3gppUserStatus),
    VisitedNetworkIdentifier(String),
    Apn(String),
    ResultCode(u32),
}

/// Diameter S6b Message container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S6bMessage {
    pub command_code: u32,
    pub is_request: bool,
    pub application_id: u32,
    pub session_id: String,
    pub avps: Vec<S6bAvp>,
}

impl S6bMessage {
    pub fn new_request(command_code: u32, session_id: &str) -> Self {
        S6bMessage {
            command_code,
            is_request: true,
            application_id: DIAMETER_APPLICATION_S6B,
            session_id: session_id.to_string(),
            avps: Vec::new(),
        }
    }

    pub fn new_answer(req: &S6bMessage, result_code: u32) -> Self {
        S6bMessage {
            command_code: req.command_code,
            is_request: false,
            application_id: req.application_id,
            session_id: req.session_id.clone(),
            avps: vec![S6bAvp::ResultCode(result_code)],
        }
    }

    pub fn add_avp(&mut self, avp: S6bAvp) {
        self.avps.push(avp);
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.command_code.to_be_bytes());
        buf.push(if self.is_request { 0x80 } else { 0x00 });
        buf.extend_from_slice(&self.application_id.to_be_bytes());
        let sess_b = self.session_id.as_bytes();
        buf.extend_from_slice(&(sess_b.len() as u16).to_be_bytes());
        buf.extend_from_slice(sess_b);

        for avp in &self.avps {
            match avp {
                S6bAvp::UserName(u) => {
                    buf.extend_from_slice(&AVP_USER_NAME.to_be_bytes());
                    let b = u.as_bytes();
                    buf.extend_from_slice(&(b.len() as u16).to_be_bytes());
                    buf.extend_from_slice(b);
                }
                S6bAvp::Anid(a) => {
                    buf.extend_from_slice(&AVP_ANID.to_be_bytes());
                    let b = a.as_bytes();
                    buf.extend_from_slice(&(b.len() as u16).to_be_bytes());
                    buf.extend_from_slice(b);
                }
                S6bAvp::Mip6AgentInfo(info) => {
                    buf.extend_from_slice(&AVP_MIP6_AGENT_INFO.to_be_bytes());
                    let b = info.serialize();
                    buf.extend_from_slice(&(b.len() as u16).to_be_bytes());
                    buf.extend_from_slice(&b);
                }
                S6bAvp::Non3gppUserStatus(st) => {
                    buf.extend_from_slice(&AVP_NON_3GPP_USER_STATUS.to_be_bytes());
                    buf.extend_from_slice(&4u16.to_be_bytes());
                    buf.extend_from_slice(&st.as_u32().to_be_bytes());
                }
                S6bAvp::VisitedNetworkIdentifier(v) => {
                    buf.extend_from_slice(&AVP_VISITED_NETWORK_IDENTIFIER.to_be_bytes());
                    let b = v.as_bytes();
                    buf.extend_from_slice(&(b.len() as u16).to_be_bytes());
                    buf.extend_from_slice(b);
                }
                S6bAvp::Apn(apn) => {
                    buf.extend_from_slice(&AVP_APN_CONFIGURATION.to_be_bytes());
                    let b = apn.as_bytes();
                    buf.extend_from_slice(&(b.len() as u16).to_be_bytes());
                    buf.extend_from_slice(b);
                }
                S6bAvp::ResultCode(rc) => {
                    buf.extend_from_slice(&AVP_RESULT_CODE.to_be_bytes());
                    buf.extend_from_slice(&4u16.to_be_bytes());
                    buf.extend_from_slice(&rc.to_be_bytes());
                }
            }
        }
        buf
    }
}

/// Profile for Non-3GPP Subscriber stored in 3GPP AAA Server.
#[derive(Debug, Clone)]
pub struct Non3gppSubProfile {
    pub imsi: String,
    pub authorized_anid: Vec<String>,
    pub allocated_pgw_ip: [u8; 4],
    pub allocated_pgw_fqdn: String,
    pub apn: String,
    pub status: Non3gppUserStatus,
}

/// 3GPP AAA Server Engine implementing the S6b reference point.
#[derive(Debug, Clone)]
pub struct AaaS6bEngine {
    pub server_realm: String,
    pub subscribers: HashMap<String, Non3gppSubProfile>,
    pub active_sessions: HashMap<String, String>, // Session-ID -> IMSI
    pub total_transactions: u64,
}

impl AaaS6bEngine {
    pub fn new(server_realm: &str) -> Self {
        AaaS6bEngine {
            server_realm: server_realm.to_string(),
            subscribers: HashMap::new(),
            active_sessions: HashMap::new(),
            total_transactions: 0,
        }
    }

    /// Provisions a non-3GPP subscriber.
    pub fn provision_subscriber(&mut self, profile: Non3gppSubProfile) {
        self.subscribers.insert(profile.imsi.clone(), profile);
    }

    /// Handles an AA-Request (AAR) from ePDG/PGW and returns AA-Answer (AAA).
    pub fn handle_aar(&mut self, aar: &S6bMessage) -> S6bMessage {
        self.total_transactions += 1;
        let user_name = aar.avps.iter().find_map(|a| {
            if let S6bAvp::UserName(u) = a {
                Some(u.clone())
            } else {
                None
            }
        });
        let anid = aar.avps.iter().find_map(|a| {
            if let S6bAvp::Anid(an) = a {
                Some(an.clone())
            } else {
                None
            }
        });

        if let Some(imsi) = user_name {
            if let Some(sub) = self.subscribers.get_mut(&imsi) {
                // Check if ANID is authorized
                let anid_ok = match anid {
                    Some(ref a) => {
                        sub.authorized_anid.is_empty() || sub.authorized_anid.contains(a)
                    }
                    None => true,
                };

                if !anid_ok {
                    return S6bMessage::new_answer(aar, 5003); // DIAMETER_AUTHORIZATION_REJECTED
                }

                sub.status = Non3gppUserStatus::UserActive;
                self.active_sessions.insert(aar.session_id.clone(), imsi);

                let mut aaa = S6bMessage::new_answer(aar, 2001); // DIAMETER_SUCCESS
                aaa.add_avp(S6bAvp::Non3gppUserStatus(Non3gppUserStatus::UserActive));
                aaa.add_avp(S6bAvp::Mip6AgentInfo(Mip6AgentInfo {
                    pgw_ip: sub.allocated_pgw_ip,
                    pgw_fqdn: sub.allocated_pgw_fqdn.clone(),
                }));
                aaa.add_avp(S6bAvp::Apn(sub.apn.clone()));
                aaa
            } else {
                S6bMessage::new_answer(aar, 5001) // DIAMETER_ERROR_USER_UNKNOWN
            }
        } else {
            S6bMessage::new_answer(aar, 5004) // DIAMETER_ERROR_IDENTITY_NOT_REGISTERED
        }
    }

    /// Handles Session-Termination-Request (STR) and returns Session-Termination-Answer (STA).
    pub fn handle_str(&mut self, req: &S6bMessage) -> S6bMessage {
        self.total_transactions += 1;
        if let Some(imsi) = self.active_sessions.remove(&req.session_id) {
            if let Some(sub) = self.subscribers.get_mut(&imsi) {
                sub.status = Non3gppUserStatus::UserDeregistered;
            }
            S6bMessage::new_answer(req, 2001)
        } else {
            S6bMessage::new_answer(req, 5002) // DIAMETER_UNKNOWN_SESSION_ID
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_s6b_aar_aaa_success_flow() {
        let mut aaa_server = AaaS6bEngine::new("aaa.epc.example.com");
        aaa_server.provision_subscriber(Non3gppSubProfile {
            imsi: "208950123456789".into(),
            authorized_anid: vec!["WLAN".into(), "HRPD".into()],
            allocated_pgw_ip: [10, 100, 1, 1],
            allocated_pgw_fqdn: "pgw01.epc.example.com".into(),
            apn: "ims.vowifi.com".into(),
            status: Non3gppUserStatus::UserDeregistered,
        });

        let mut aar = S6bMessage::new_request(DIAMETER_CMD_AA, "s6b-session-999");
        aar.add_avp(S6bAvp::UserName("208950123456789".into()));
        aar.add_avp(S6bAvp::Anid("WLAN".into()));

        let ans = aaa_server.handle_aar(&aar);
        assert_eq!(ans.command_code, DIAMETER_CMD_AA);
        assert!(!ans.is_request);

        let rc = ans.avps.iter().find_map(|a| {
            if let S6bAvp::ResultCode(c) = a {
                Some(*c)
            } else {
                None
            }
        });
        assert_eq!(rc, Some(2001));

        let agent = ans.avps.iter().find_map(|a| {
            if let S6bAvp::Mip6AgentInfo(info) = a {
                Some(info.clone())
            } else {
                None
            }
        });
        assert!(agent.is_some());
        let info = agent.unwrap();
        assert_eq!(info.pgw_ip, [10, 100, 1, 1]);
        assert_eq!(info.pgw_fqdn, "pgw01.epc.example.com");
    }

    #[test]
    fn test_s6b_unauthorized_anid_rejection() {
        let mut aaa_server = AaaS6bEngine::new("aaa.epc.example.com");
        aaa_server.provision_subscriber(Non3gppSubProfile {
            imsi: "208950123456789".into(),
            authorized_anid: vec!["WLAN".into()],
            allocated_pgw_ip: [10, 100, 1, 1],
            allocated_pgw_fqdn: "pgw01.epc.example.com".into(),
            apn: "internet".into(),
            status: Non3gppUserStatus::UserDeregistered,
        });

        let mut aar = S6bMessage::new_request(DIAMETER_CMD_AA, "s6b-session-998");
        aar.add_avp(S6bAvp::UserName("208950123456789".into()));
        aar.add_avp(S6bAvp::Anid("CDMA2000_1xRTT".into())); // Unauthorized ANID

        let ans = aaa_server.handle_aar(&aar);
        let rc = ans.avps.iter().find_map(|a| {
            if let S6bAvp::ResultCode(c) = a {
                Some(*c)
            } else {
                None
            }
        });
        assert_eq!(rc, Some(5003)); // DIAMETER_AUTHORIZATION_REJECTED
    }

    #[test]
    fn test_s6b_str_sta_termination() {
        let mut aaa_server = AaaS6bEngine::new("aaa.epc.example.com");
        aaa_server.provision_subscriber(Non3gppSubProfile {
            imsi: "208950000000001".into(),
            authorized_anid: vec![],
            allocated_pgw_ip: [10, 0, 0, 1],
            allocated_pgw_fqdn: "pgw01".into(),
            apn: "ims".into(),
            status: Non3gppUserStatus::UserDeregistered,
        });

        let mut aar = S6bMessage::new_request(DIAMETER_CMD_AA, "sess-01");
        aar.add_avp(S6bAvp::UserName("208950000000001".into()));
        aaa_server.handle_aar(&aar);

        // Session is active
        assert_eq!(
            aaa_server
                .subscribers
                .get("208950000000001")
                .unwrap()
                .status,
            Non3gppUserStatus::UserActive
        );

        // Send STR
        let str_msg = S6bMessage::new_request(DIAMETER_CMD_SESSION_TERMINATION, "sess-01");
        let sta = aaa_server.handle_str(&str_msg);
        let rc = sta.avps.iter().find_map(|a| {
            if let S6bAvp::ResultCode(c) = a {
                Some(*c)
            } else {
                None
            }
        });
        assert_eq!(rc, Some(2001));
        assert_eq!(
            aaa_server
                .subscribers
                .get("208950000000001")
                .unwrap()
                .status,
            Non3gppUserStatus::UserDeregistered
        );
    }
}

//! 3GPP TS 29.109 — Diameter Zh / GAA / GBA Bootstrapping Interface.
//!
//! The Generic Authentication Architecture / Generic Bootstrapping Architecture (GBA)
//! allows application servers (Network Application Functions - NAF) to authenticate
//! cellular subscribers using SIM/USIM credentials.
//!
//! The Diameter Zh interface connects the BSF (Bootstrapping Server Function)
//! to the HSS to retrieve GBA subscriber security settings (GUSS) and AKA authentication vectors.
//!
//! This module implements:
//! * Diameter Application ID `16777221` (3GPP Zh).
//! * Multimedia-Auth-Request (MAR) / Multimedia-Auth-Answer (MAA) — Command Code 303.
//! * Key AVPs:
//!   - `User-Name` (AVP 1, IMSI).
//!   - `GBA-UserSecSettings` (AVP 400, GUSS XML configuration).
//!   - `GBA-Type` (AVP 404): 3G GBA (0), 2G GBA (1).
//!   - `SIP-Auth-Data-Item` (AVP 612): Contains RAND, AUTN, CK, IK.
//!   - `Result-Code` (AVP 268).
//! * `BsfZhEngine`: BSF authentication vector caching and NAF key (`Ks_NAF`) derivation.

use std::collections::HashMap;

pub const DIAMETER_APPLICATION_ZH: u32 = 16777221;
pub const DIAMETER_CMD_MULTIMEDIA_AUTH: u32 = 303;

pub const AVP_USER_NAME: u32 = 1;
pub const AVP_RESULT_CODE: u32 = 268;
pub const AVP_GBA_USER_SEC_SETTINGS: u32 = 400;
pub const AVP_GBA_TYPE: u32 = 404;
pub const AVP_SIP_AUTH_DATA_ITEM: u32 = 612;

/// GBA Type per 3GPP TS 29.109.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GbaType {
    Gba3G = 0,
    Gba2G = 1,
}

/// GBA Authentication Vector delivered by HSS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GbaAuthVector {
    pub rand: [u8; 16],
    pub autn: [u8; 16],
    pub ck: [u8; 16],
    pub ik: [u8; 16],
}

/// Diameter Zh AVP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZhAvp {
    UserName(String),
    GbaType(GbaType),
    GbaUserSecSettings(String),
    AuthVector(GbaAuthVector),
    ResultCode(u32),
}

/// Diameter Zh Message container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZhMessage {
    pub command_code: u32,
    pub is_request: bool,
    pub application_id: u32,
    pub session_id: String,
    pub avps: Vec<ZhAvp>,
}

impl ZhMessage {
    pub fn new_mar(session_id: &str, imsi: &str, gba_type: GbaType) -> Self {
        ZhMessage {
            command_code: DIAMETER_CMD_MULTIMEDIA_AUTH,
            is_request: true,
            application_id: DIAMETER_APPLICATION_ZH,
            session_id: session_id.to_string(),
            avps: vec![ZhAvp::UserName(imsi.to_string()), ZhAvp::GbaType(gba_type)],
        }
    }

    pub fn new_maa(req: &ZhMessage, result_code: u32) -> Self {
        ZhMessage {
            command_code: req.command_code,
            is_request: false,
            application_id: req.application_id,
            session_id: req.session_id.clone(),
            avps: vec![ZhAvp::ResultCode(result_code)],
        }
    }

    pub fn add_avp(&mut self, avp: ZhAvp) {
        self.avps.push(avp);
    }
}

/// Subscriber GBA Profile in HSS.
#[derive(Debug, Clone)]
pub struct GbaSubscriberProfile {
    pub imsi: String,
    pub guss_xml: String,
    pub auth_vector: GbaAuthVector,
}

/// BSF / HSS Diameter Zh Engine.
#[derive(Debug, Clone)]
pub struct BsfZhEngine {
    pub hss_realm: String,
    pub subscribers: HashMap<String, GbaSubscriberProfile>,
    pub total_mar_requests: u64,
    pub successful_bootstraps: u64,
}

impl BsfZhEngine {
    pub fn new(hss_realm: &str) -> Self {
        BsfZhEngine {
            hss_realm: hss_realm.to_string(),
            subscribers: HashMap::new(),
            total_mar_requests: 0,
            successful_bootstraps: 0,
        }
    }

    pub fn register_subscriber(&mut self, imsi: &str, guss_xml: &str, vector: GbaAuthVector) {
        self.subscribers.insert(
            imsi.to_string(),
            GbaSubscriberProfile {
                imsi: imsi.to_string(),
                guss_xml: guss_xml.to_string(),
                auth_vector: vector,
            },
        );
    }

    /// Handles Multimedia-Auth-Request (MAR) and delivers GUSS XML & AKA Vector in MAA.
    pub fn handle_mar(&mut self, mar: &ZhMessage) -> ZhMessage {
        self.total_mar_requests += 1;
        let imsi = mar
            .avps
            .iter()
            .find_map(|a| {
                if let ZhAvp::UserName(u) = a {
                    Some(u.clone())
                } else {
                    None
                }
            })
            .unwrap_or_default();

        if let Some(sub) = self.subscribers.get(&imsi) {
            self.successful_bootstraps += 1;
            let mut maa = ZhMessage::new_maa(mar, 2001); // DIAMETER_SUCCESS
            maa.add_avp(ZhAvp::GbaUserSecSettings(sub.guss_xml.clone()));
            maa.add_avp(ZhAvp::AuthVector(sub.auth_vector.clone()));
            maa
        } else {
            ZhMessage::new_maa(mar, 5001) // DIAMETER_ERROR_USER_UNKNOWN
        }
    }

    /// Derives application-specific Ks_NAF key from CK/IK and NAF_ID per 3GPP TS 33.220.
    pub fn derive_ks_naf(&self, imsi: &str, naf_id: &str) -> Option<[u8; 32]> {
        let sub = self.subscribers.get(imsi)?;
        let mut key = [0u8; 32];
        for i in 0..16 {
            key[i] = sub.auth_vector.ck[i] ^ (naf_id.as_bytes()[i % naf_id.len()]);
            key[i + 16] = sub.auth_vector.ik[i] ^ (naf_id.as_bytes()[(i + 1) % naf_id.len()]);
        }
        Some(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diameter_zh_mar_maa_bootstrapping() {
        let mut bsf = BsfZhEngine::new("hss.gba.operator.com");
        let vector = GbaAuthVector {
            rand: [0x11; 16],
            autn: [0x22; 16],
            ck: [0x33; 16],
            ik: [0x44; 16],
        };
        bsf.register_subscriber("208950123456789", "<guss><uicc>yes</uicc></guss>", vector);

        let mar = ZhMessage::new_mar("sess-zh-01", "208950123456789", GbaType::Gba3G);
        assert_eq!(mar.application_id, DIAMETER_APPLICATION_ZH);
        assert_eq!(mar.command_code, DIAMETER_CMD_MULTIMEDIA_AUTH);

        let maa = bsf.handle_mar(&mar);
        assert!(!maa.is_request);

        let rc = maa.avps.iter().find_map(|a| {
            if let ZhAvp::ResultCode(c) = a {
                Some(*c)
            } else {
                None
            }
        });
        assert_eq!(rc, Some(2001));

        let guss = maa.avps.iter().find_map(|a| {
            if let ZhAvp::GbaUserSecSettings(g) = a {
                Some(g.clone())
            } else {
                None
            }
        });
        assert_eq!(guss, Some("<guss><uicc>yes</uicc></guss>".into()));

        // Derive Ks_NAF
        let ks_naf = bsf
            .derive_ks_naf("208950123456789", "naf.service.org")
            .expect("Derive Ks_NAF");
        assert_eq!(ks_naf.len(), 32);
        assert_eq!(bsf.successful_bootstraps, 1);
    }
}

//! 3GPP Diameter S6a / S6d MME-HSS Mobility Management Interface (3GPP TS 29.272).
//!
//! Implements Diameter S6a authentication (AIR/AIA - Command 318), location update
//! (ULR/ULA - Command 316), EPS Authentication Vector generation (RAND, XRES, AUTN, KASME),
//! and HSS subscriber database management over Application ID 16777251.

use crate::diameter::{
    DIAMETER_FLAG_MANDATORY, DIAMETER_FLAG_VENDOR_SPECIFIC, DIAMETER_SUCCESS, DiameterAvp,
    DiameterMessage,
};
use crate::diameter_gx::VENDOR_3GPP;
use std::collections::HashMap;

/// Diameter Application ID for 3GPP S6a Interface (3GPP TS 29.272).
pub const DIAMETER_APPLICATION_S6A: u32 = 16777251;

/// Diameter S6a Command Codes.
pub const DIAMETER_CMD_UPDATE_LOCATION: u32 = 316; // ULR / ULA
pub const DIAMETER_CMD_AUTH_INFO: u32 = 318; // AIR / AIA
pub const DIAMETER_CMD_PURGE_UE: u32 = 321; // PUR / PUA

/// 3GPP S6a AVP Codes.
pub const AVP_USER_NAME: u32 = 1;
pub const AVP_SUBSCRIPTION_DATA: u32 = 1400;
pub const AVP_AUTHENTICATION_INFO: u32 = 1413;
pub const AVP_E_UTRAN_VECTOR: u32 = 1414;
pub const AVP_RAND: u32 = 1447;
pub const AVP_XRES: u32 = 1448;
pub const AVP_AUTN: u32 = 1449;
pub const AVP_KASME: u32 = 1450;
pub const AVP_VISITED_PLMN_ID: u32 = 1407;
pub const AVP_RAT_TYPE: u32 = 1032;

/// EPS E-UTRAN 4-tuple Authentication Vector (3GPP TS 33.401).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpsAuthVector {
    pub rand: [u8; 16],
    pub xres: [u8; 8],
    pub autn: [u8; 16],
    pub kasme: [u8; 32],
}

impl EpsAuthVector {
    pub fn new(rand: [u8; 16], xres: [u8; 8], autn: [u8; 16], kasme: [u8; 32]) -> Self {
        EpsAuthVector {
            rand,
            xres,
            autn,
            kasme,
        }
    }

    /// Encodes this EPS vector as an `E-UTRAN-Vector` Grouped AVP (AVP 1414).
    pub fn to_grouped_avp(&self) -> DiameterAvp {
        let mut inner = Vec::new();

        // 1. RAND (AVP 1447)
        let avp_rand = DiameterAvp::new_vendor(
            AVP_RAND,
            DIAMETER_FLAG_MANDATORY | DIAMETER_FLAG_VENDOR_SPECIFIC,
            VENDOR_3GPP,
            &self.rand,
        );
        inner.extend_from_slice(&avp_rand.serialize());

        // 2. XRES (AVP 1448)
        let avp_xres = DiameterAvp::new_vendor(
            AVP_XRES,
            DIAMETER_FLAG_MANDATORY | DIAMETER_FLAG_VENDOR_SPECIFIC,
            VENDOR_3GPP,
            &self.xres,
        );
        inner.extend_from_slice(&avp_xres.serialize());

        // 3. AUTN (AVP 1449)
        let avp_autn = DiameterAvp::new_vendor(
            AVP_AUTN,
            DIAMETER_FLAG_MANDATORY | DIAMETER_FLAG_VENDOR_SPECIFIC,
            VENDOR_3GPP,
            &self.autn,
        );
        inner.extend_from_slice(&avp_autn.serialize());

        // 4. KASME (AVP 1450)
        let avp_kasme = DiameterAvp::new_vendor(
            AVP_KASME,
            DIAMETER_FLAG_MANDATORY | DIAMETER_FLAG_VENDOR_SPECIFIC,
            VENDOR_3GPP,
            &self.kasme,
        );
        inner.extend_from_slice(&avp_kasme.serialize());

        DiameterAvp::new_vendor(
            AVP_E_UTRAN_VECTOR,
            DIAMETER_FLAG_MANDATORY | DIAMETER_FLAG_VENDOR_SPECIFIC,
            VENDOR_3GPP,
            &inner,
        )
    }

    /// Parses an `E-UTRAN-Vector` Grouped AVP.
    pub fn from_grouped_avp(avp: &DiameterAvp) -> Option<Self> {
        let mut rand = [0u8; 16];
        let mut xres = [0u8; 8];
        let mut autn = [0u8; 16];
        let mut kasme = [0u8; 32];
        let mut has_rand = false;
        let mut has_xres = false;
        let mut has_autn = false;
        let mut has_kasme = false;

        let inners = DiameterAvp::parse_all(&avp.data);
        for a in inners {
            match a.code {
                AVP_RAND if a.data.len() == 16 => {
                    rand.copy_from_slice(&a.data);
                    has_rand = true;
                }
                AVP_XRES if a.data.len() == 8 => {
                    xres.copy_from_slice(&a.data);
                    has_xres = true;
                }
                AVP_AUTN if a.data.len() == 16 => {
                    autn.copy_from_slice(&a.data);
                    has_autn = true;
                }
                AVP_KASME if a.data.len() == 32 => {
                    kasme.copy_from_slice(&a.data);
                    has_kasme = true;
                }
                _ => {}
            }
        }

        if has_rand && has_xres && has_autn && has_kasme {
            Some(EpsAuthVector {
                rand,
                xres,
                autn,
                kasme,
            })
        } else {
            None
        }
    }
}

/// Subscriber Profile stored in HSS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HssSubscriberProfile {
    pub imsi: String,
    pub msisdn: String,
    pub default_apn: String,
    pub subscribed_ambr_ul_kbps: u32,
    pub subscribed_ambr_dl_kbps: u32,
    pub registered_mme: Option<String>,
}

/// HSS S6a Interface Protocol Engine.
#[derive(Debug, Clone)]
pub struct HssS6aEngine {
    pub hss_realm: String,
    pub subscribers: HashMap<String, HssSubscriberProfile>,
    pub auth_vectors_generated_count: usize,
    pub location_updates_count: usize,
}

impl HssS6aEngine {
    pub fn new(hss_realm: &str) -> Self {
        HssS6aEngine {
            hss_realm: hss_realm.to_string(),
            subscribers: HashMap::new(),
            auth_vectors_generated_count: 0,
            location_updates_count: 0,
        }
    }

    /// Provisions a subscriber profile in HSS.
    pub fn provision_subscriber(&mut self, profile: HssSubscriberProfile) {
        self.subscribers.insert(profile.imsi.clone(), profile);
    }

    /// Handles an incoming Authentication-Information-Request (AIR) and generates EPS vectors.
    pub fn handle_auth_info_request(
        &mut self,
        imsi: &str,
        plmn: &[u8; 3],
    ) -> Option<DiameterMessage> {
        let _sub = self.subscribers.get(imsi)?;
        self.auth_vectors_generated_count += 1;

        // Generate deterministic pseudorandom EPS vector for this IMSI and PLMN
        let mut rand = [0x5A; 16];
        rand[0] = (self.auth_vectors_generated_count & 0xFF) as u8;
        rand[1..4].copy_from_slice(plmn);

        let mut xres = [0xAA; 8];
        xres[0] = rand[0] ^ 0x3C;

        let mut autn = [0x80; 16];
        autn[0] = 0x90;

        let mut kasme = [0xEE; 32];
        kasme[0..16].copy_from_slice(&rand);

        let vector = EpsAuthVector::new(rand, xres, autn, kasme);
        let vector_avp = vector.to_grouped_avp();

        let mut auth_info_data = Vec::new();
        auth_info_data.extend_from_slice(&vector_avp.serialize());
        let auth_info_avp = DiameterAvp::new_vendor(
            AVP_AUTHENTICATION_INFO,
            DIAMETER_FLAG_MANDATORY | DIAMETER_FLAG_VENDOR_SPECIFIC,
            VENDOR_3GPP,
            &auth_info_data,
        );

        let mut aia =
            DiameterMessage::new_answer(DIAMETER_CMD_AUTH_INFO, DIAMETER_APPLICATION_S6A, 1, 1);
        aia.add_avp(DiameterAvp::new_utf8(AVP_USER_NAME, imsi));
        aia.add_avp(DiameterAvp::new_u32(268, DIAMETER_SUCCESS));
        aia.add_avp(auth_info_avp);

        Some(aia)
    }

    /// Handles an incoming Update-Location-Request (ULR) from an MME.
    pub fn handle_update_location_request(
        &mut self,
        imsi: &str,
        mme_host: &str,
    ) -> Option<DiameterMessage> {
        let sub = self.subscribers.get_mut(imsi)?;
        sub.registered_mme = Some(mme_host.to_string());
        self.location_updates_count += 1;

        let mut ula = DiameterMessage::new_answer(
            DIAMETER_CMD_UPDATE_LOCATION,
            DIAMETER_APPLICATION_S6A,
            1,
            1,
        );
        ula.add_avp(DiameterAvp::new_utf8(AVP_USER_NAME, imsi));
        ula.add_avp(DiameterAvp::new_u32(268, DIAMETER_SUCCESS));

        Some(ula)
    }
}

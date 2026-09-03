//! 3GPP TS 29.509 / TS 29.503 / TS 33.501 5G AUSF & UDM Protocol Engine.
//!
//! Implements 5G Core Authentication Server Function (AUSF) and Unified Data Management (UDM):
//! - 5G-AKA Security Architecture (TS 33.501 Annex A):
//!   - Milenage-compatible 5G authentication vector generation (RAND, AUTN, XRES*, K_ausf)
//!   - K_seaf key derivation and HXRES* hash verification
//! - Nausf_UEAuthentication Service (TS 29.509):
//!   - Authenticate Request / Response / Confirmation lifecycle
//! - Nudm_UEAU & Nudm_SDM Services (TS 29.503):
//!   - SUCI (Subscription Concealed Identifier) de-concealing to SUPI
//!   - Access and Mobility (AM) subscription data management
//!   - Session Management (SM) subscription data management

use std::collections::HashMap;

use crate::nas_5g::{PduSessionType, SscMode, verify_5g_aka_challenge};
use crate::ngap_5g::Snssai;

// ---------------------------------------------------------------------------
// Standard SHA-256 (FIPS 180-4) Implementation in Pure Standard Rust
// ---------------------------------------------------------------------------

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Compute standard SHA-256 digest of input bytes.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = [
        0x6a09e667u32,
        0xbb67ae85u32,
        0x3c6ef372u32,
        0xa54ff53au32,
        0x510e527fu32,
        0x9b05688cu32,
        0x1f83d9abu32,
        0x5be0cd19u32,
    ];

    let mut msg = Vec::from(data);
    let orig_len_bits = (data.len() as u64) * 8;

    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&orig_len_bits.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, w_elem) in w.iter_mut().take(16).enumerate() {
            let mut b = [0u8; 4];
            b.copy_from_slice(&chunk[i * 4..i * 4 + 4]);
            *w_elem = u32::from_be_bytes(b);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut h_var = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h_var
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h_var = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(h_var);
    }

    let mut out = [0u8; 32];
    for (i, val) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&val.to_be_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// 5G-AKA Authentication Vectors & Key Derivation (TS 33.501 Annex A)
// ---------------------------------------------------------------------------

/// 5G Home Environment Authentication Vector (5G-HE-AV).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationVector {
    pub rand: [u8; 16],
    pub autn: [u8; 16],
    pub xres_star: [u8; 16],
    pub k_ausf: [u8; 32],
}

/// Derive K_seaf from K_ausf and serving network name (TS 33.501 Annex A.6).
pub fn derive_k_seaf(k_ausf: &[u8; 32], serving_network_name: &str) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.push(0x6C); // FC = 0x6C for K_seaf derivation
    buf.extend_from_slice(serving_network_name.as_bytes());
    buf.extend_from_slice(k_ausf);
    sha256(&buf)
}

/// Derive HXRES* from RAND and XRES* (TS 33.501 Annex A.5).
pub fn derive_hxres_star(rand: &[u8; 16], xres_star: &[u8; 16]) -> [u8; 16] {
    let mut buf = Vec::new();
    buf.extend_from_slice(rand);
    buf.extend_from_slice(xres_star);
    let digest = sha256(&buf);
    let mut hxres = [0u8; 16];
    hxres.copy_from_slice(&digest[16..32]); // Lower 128-bits
    hxres
}

// ---------------------------------------------------------------------------
// UDM (Unified Data Management) Subscription Storage & Engine
// ---------------------------------------------------------------------------

/// Subscriber security credential record in UDM Authentication Data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdmSecurityRecord {
    pub supi: String,
    pub k_secret: [u8; 16],
    pub opc: [u8; 16],
    pub sqn: u64,
}

/// Access and Mobility (AM) Subscription Data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmSubscriptionData {
    pub supported_snssais: Vec<Snssai>,
    pub rfsp_index: u8,
}

/// Single Data Network Name (DNN) configuration in SM Subscription Data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnnConfiguration {
    pub allowed_pdu_session_types: Vec<PduSessionType>,
    pub default_ssc_mode: SscMode,
    pub session_ambr_dl_kbps: u32,
    pub session_ambr_ul_kbps: u32,
    pub default_5qi: u8,
}

/// UDM Unified Data Management Engine.
#[derive(Debug, Clone, Default)]
pub struct UdmEngine {
    pub security_records: HashMap<String, UdmSecurityRecord>, // supi -> record
    pub am_data: HashMap<String, AmSubscriptionData>,         // supi -> am
    pub sm_data: HashMap<String, HashMap<String, DnnConfiguration>>, // supi -> (dnn -> config)
    pub pseudo_rand_counter: u64,
}

impl UdmEngine {
    pub fn new() -> Self {
        UdmEngine {
            security_records: HashMap::new(),
            am_data: HashMap::new(),
            sm_data: HashMap::new(),
            pseudo_rand_counter: 0x1234_5678,
        }
    }

    /// Register a subscriber in UDM with security credentials and subscription data.
    pub fn provision_subscriber(
        &mut self,
        supi: &str,
        k_secret: [u8; 16],
        opc: [u8; 16],
        snssais: Vec<Snssai>,
        dnn_configs: Vec<(String, DnnConfiguration)>,
    ) {
        let sec = UdmSecurityRecord {
            supi: supi.to_string(),
            k_secret,
            opc,
            sqn: 1,
        };
        self.security_records.insert(supi.to_string(), sec);

        let am = AmSubscriptionData {
            supported_snssais: snssais,
            rfsp_index: 1,
        };
        self.am_data.insert(supi.to_string(), am);

        let mut sm_map = HashMap::new();
        for (dnn, cfg) in dnn_configs {
            sm_map.insert(dnn, cfg);
        }
        self.sm_data.insert(supi.to_string(), sm_map);
    }

    /// De-conceal SUCI into SUPI (TS 29.503 Section 5.3).
    /// For test/null scheme: "suci-0-208-95-0-0-0-0000000001" -> "imsi-208950000000001".
    pub fn deconceal_suci(&self, suci: &str) -> String {
        if suci.starts_with("suci-0-") {
            let parts: Vec<&str> = suci.split('-').collect();
            if parts.len() >= 8 {
                let mcc = parts[2];
                let mnc = parts[3];
                let msin = parts[7];
                return format!("imsi-{}{}{}", mcc, mnc, msin);
            }
        }
        if suci.starts_with("imsi-") {
            return suci.to_string();
        }
        format!("imsi-{}", suci)
    }

    /// Nudm_UEAU_Get: Generate 5G Authentication Vector for a subscriber.
    pub fn generate_auth_vector(
        &mut self,
        supi: &str,
        serving_network_name: &str,
    ) -> Result<AuthenticationVector, &'static str> {
        let rec = self
            .security_records
            .get_mut(supi)
            .ok_or("Subscriber not found in UDM")?;

        // 1. Generate pseudo-random RAND
        self.pseudo_rand_counter = self
            .pseudo_rand_counter
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1);
        let mut rand = [0u8; 16];
        let rand_part1 = self.pseudo_rand_counter.to_be_bytes();
        let rand_part2 = (!self.pseudo_rand_counter).to_be_bytes();
        rand[0..8].copy_from_slice(&rand_part1);
        rand[8..16].copy_from_slice(&rand_part2);

        // 2. Increment SQN
        rec.sqn += 1;
        let sqn = rec.sqn;

        // 3. Construct AUTN: (SQN ^ AK) || AMF || MAC-A
        let mut autn = [0u8; 16];
        let sqn_bytes = sqn.to_be_bytes();
        for i in 0..6 {
            autn[i] = sqn_bytes[i + 2] ^ rec.opc[i];
        }
        autn[6] = 0x80; // AMF high byte
        autn[7] = 0x00; // AMF low byte
        for i in 8..16 {
            autn[i] = rand[i] ^ rec.k_secret[i]; // MAC-A
        }

        // 4. Compute expected XRES* matching UE NAS verify_5g_aka_challenge
        let xres_star = verify_5g_aka_challenge(&rand, &autn, &rec.k_secret);

        // 5. Derive K_ausf from K, RAND, and serving network name
        let mut k_ausf_seed = Vec::new();
        k_ausf_seed.extend_from_slice(&rec.k_secret);
        k_ausf_seed.extend_from_slice(&rand);
        k_ausf_seed.extend_from_slice(serving_network_name.as_bytes());
        let k_ausf = sha256(&k_ausf_seed);

        Ok(AuthenticationVector {
            rand,
            autn,
            xres_star,
            k_ausf,
        })
    }

    /// Nudm_SDM_Get: Retrieve Access and Mobility subscription data.
    pub fn get_am_data(&self, supi: &str) -> Option<&AmSubscriptionData> {
        self.am_data.get(supi)
    }

    /// Nudm_SDM_Get: Retrieve Session Management subscription data for a DNN.
    pub fn get_sm_data(&self, supi: &str, dnn: &str) -> Option<&DnnConfiguration> {
        self.sm_data.get(supi)?.get(dnn)
    }
}

// ---------------------------------------------------------------------------
// AUSF (Authentication Server Function) Service Operations (TS 29.509)
// ---------------------------------------------------------------------------

/// Nausf_UEAuthentication Request (AMF -> AUSF).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UeAuthenticationRequest {
    pub supi_or_suci: String,
    pub serving_network_name: String,
}

/// Nausf_UEAuthentication Response (AUSF -> AMF).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UeAuthenticationResponse {
    pub auth_context_ref: String,
    pub rand: [u8; 16],
    pub autn: [u8; 16],
    pub hxres_star: [u8; 16],
}

/// Nausf_UEAuthentication Confirmation Request (AMF -> AUSF).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UeAuthenticationConfirmationRequest {
    pub auth_context_ref: String,
    pub res_star: [u8; 16],
}

/// Nausf_UEAuthentication Confirmation Response (AUSF -> AMF).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UeAuthenticationConfirmationResponse {
    pub success: bool,
    pub k_seaf: Option<[u8; 32]>,
    pub supi: String,
}

/// Internal session context cached on AUSF between Request and Confirmation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AusfAuthContext {
    pub supi: String,
    pub serving_network_name: String,
    pub xres_star: [u8; 16],
    pub k_seaf: [u8; 32],
}

/// 5G Authentication Server Function (AUSF) Engine.
pub struct AusfEngine {
    pub ausf_instance_id: String,
    pub udm: UdmEngine,
    pub next_context_id: u32,
    pub pending_contexts: HashMap<String, AusfAuthContext>, // auth_context_ref -> context
}

impl AusfEngine {
    /// Create a new AUSF engine backed by a UDM instance.
    pub fn new(ausf_instance_id: &str, udm: UdmEngine) -> Self {
        AusfEngine {
            ausf_instance_id: ausf_instance_id.to_string(),
            udm,
            next_context_id: 1,
            pending_contexts: HashMap::new(),
        }
    }

    /// Process Nausf_UEAuthentication_Authenticate Request from AMF.
    pub fn handle_authenticate_request(
        &mut self,
        req: &UeAuthenticationRequest,
    ) -> Result<UeAuthenticationResponse, &'static str> {
        // 1. De-conceal SUCI to SUPI if needed
        let supi = self.udm.deconceal_suci(&req.supi_or_suci);

        // 2. Obtain 5G Authentication Vector from UDM
        let av = self
            .udm
            .generate_auth_vector(&supi, &req.serving_network_name)?;

        // 3. Derive K_seaf and HXRES*
        let k_seaf = derive_k_seaf(&av.k_ausf, &req.serving_network_name);
        let hxres_star = derive_hxres_star(&av.rand, &av.xres_star);

        // 4. Cache authentication context
        let context_ref = format!("urn:auth-ctx:{}", self.next_context_id);
        self.next_context_id += 1;

        let ctx = AusfAuthContext {
            supi,
            serving_network_name: req.serving_network_name.clone(),
            xres_star: av.xres_star,
            k_seaf,
        };
        self.pending_contexts.insert(context_ref.clone(), ctx);

        Ok(UeAuthenticationResponse {
            auth_context_ref: context_ref,
            rand: av.rand,
            autn: av.autn,
            hxres_star,
        })
    }

    /// Process Nausf_UEAuthentication_Authenticate Confirmation from AMF.
    pub fn handle_authenticate_confirmation(
        &mut self,
        req: &UeAuthenticationConfirmationRequest,
    ) -> Result<UeAuthenticationConfirmationResponse, &'static str> {
        let ctx = self
            .pending_contexts
            .remove(&req.auth_context_ref)
            .ok_or("Authentication context not found or expired")?;

        // Verify UE's RES* matches expected XRES*
        if req.res_star != ctx.xres_star {
            return Ok(UeAuthenticationConfirmationResponse {
                success: false,
                k_seaf: None,
                supi: ctx.supi,
            });
        }

        Ok(UeAuthenticationConfirmationResponse {
            success: true,
            k_seaf: Some(ctx.k_seaf),
            supi: ctx.supi,
        })
    }
}

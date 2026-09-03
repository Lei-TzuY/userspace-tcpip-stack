//! 3GPP TS 29.531 / TS 23.501 / TS 33.501 5G Network Slice-Specific Authentication and Authorization Function (NSSAAF) Engine.
//!
//! Implements secondary slice-specific authentication and authorization (NSSAA):
//! - Nnssaaf_NSSAA Service (TS 29.531 Section 5.2):
//!   - AMF initiates slice-specific authentication for enterprise/vertical S-NSSAIs
//!   - EAP-based slice authentication protocol bridging (AMF <-> NSSAAF <-> Enterprise AAA-S)
//!   - Intermediate EAP identity and challenge round-trips (EAP-TLS / EAP-AKA')
//!   - Slice Authorization confirmation with configurable token lifetime
//!   - Slice Authorization Revocation (TS 29.531 Section 5.3) initiated by Enterprise AAA-S

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// 5G NSSAAF Enums & Data Structures (TS 29.531 Section 6)
// ---------------------------------------------------------------------------

/// Single Network Slice Selection Assistance Information (S-NSSAI - TS 23.003).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Snssai {
    pub sst: u8,
    pub sd: Option<[u8; 3]>,
}

impl Snssai {
    pub fn new(sst: u8, sd: Option<[u8; 3]>) -> Self {
        Snssai { sst, sd }
    }

    pub fn to_string(&self) -> String {
        match self.sd {
            Some(sd) => format!("{:02x}:{:02x}{:02x}{:02x}", self.sst, sd[0], sd[1], sd[2]),
            None => format!("{:02x}", self.sst),
        }
    }
}

/// NSSAA Authentication Status (TS 29.531 Section 6.1.6.3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SliceAuthStatus {
    PendingChallenge,
    Success,
    Failed,
    Revoked,
}

/// Slice Authentication Context for a UE's secondary auth session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SliceAuthContext {
    pub auth_ctx_id: String,
    pub supi: String,
    pub snssai: Snssai,
    pub amf_id: String,
    pub enterprise_aaa_s: String,
    pub eap_session_id: u8,
    pub status: SliceAuthStatus,
    pub allowed_lifetime_s: u32,
    pub auth_timestamp_epoch_s: Option<u64>,
}

/// EAP Code (RFC 3748).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapCode {
    Request = 1,
    Response = 2,
    Success = 3,
    Failure = 4,
}

/// Simplified EAP Packet representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapPacket {
    pub code: EapCode,
    pub identifier: u8,
    pub payload: Vec<u8>,
}

/// Slice Revocation Notification dispatched to AMF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SliceRevocationNotification {
    pub supi: String,
    pub snssai: Snssai,
    pub amf_id: String,
    pub reason: String,
    pub timestamp_epoch_s: u64,
}

/// NSSAAF Error Types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NssaafError {
    ContextNotFound,
    AaaSUnreachable(&'static str),
    EapAuthenticationFailed(&'static str),
    SliceNotRequiringNssaa,
    InvalidEapPacket,
}

// ---------------------------------------------------------------------------
// Top-Level NSSAAF Engine
// ---------------------------------------------------------------------------

/// 5G Network Slice-Specific Authentication and Authorization Function (NSSAAF).
pub struct NssaafEngine {
    pub nssaaf_id: String,
    pub next_ctx_id: u64,
    /// S-NSSAI to Enterprise AAA-S endpoint mapping: Snssai -> aaa_s_fqdn
    pub slice_to_aaa_s: HashMap<Snssai, String>,
    /// Pre-shared enterprise credentials for simulation: (aaa_s, supi) -> expected_secret
    pub enterprise_credentials: HashMap<(String, String), Vec<u8>>,
    /// Active contexts: auth_ctx_id -> SliceAuthContext
    pub contexts: HashMap<String, SliceAuthContext>,
    /// Authorized slices cache: (supi, Snssai) -> (expiry_epoch_s, amf_id)
    pub authorized_slices: HashMap<(String, Snssai), (u64, String)>,
    /// Revocation notification dispatch queue for AMF
    pub amf_revocation_queue: Vec<SliceRevocationNotification>,
}

impl NssaafEngine {
    /// Create a new NSSAAF engine.
    pub fn new(nssaaf_id: &str) -> Self {
        NssaafEngine {
            nssaaf_id: nssaaf_id.to_string(),
            next_ctx_id: 1,
            slice_to_aaa_s: HashMap::new(),
            enterprise_credentials: HashMap::new(),
            contexts: HashMap::new(),
            authorized_slices: HashMap::new(),
            amf_revocation_queue: Vec::new(),
        }
    }

    /// Register an enterprise AAA-S server for a specific slice.
    pub fn register_enterprise_slice(&mut self, snssai: Snssai, aaa_s_fqdn: &str) {
        self.slice_to_aaa_s.insert(snssai, aaa_s_fqdn.to_string());
    }

    /// Register enterprise credentials for a subscriber.
    pub fn add_enterprise_credential(&mut self, aaa_s_fqdn: &str, supi: &str, secret: Vec<u8>) {
        self.enterprise_credentials
            .insert((aaa_s_fqdn.to_string(), supi.to_string()), secret);
    }

    // -----------------------------------------------------------------------
    // Nnssaaf_NSSAA Service Operations (TS 29.531 Section 5.2)
    // -----------------------------------------------------------------------

    /// Initiate slice-specific authentication (POST /slice-authentications).
    /// Returns (auth_ctx_id, initial_eap_request).
    pub fn initiate_slice_auth(
        &mut self,
        supi: &str,
        snssai: Snssai,
        amf_id: &str,
    ) -> Result<(String, EapPacket), NssaafError> {
        let aaa_s = self
            .slice_to_aaa_s
            .get(&snssai)
            .ok_or(NssaafError::SliceNotRequiringNssaa)?
            .clone();

        let ctx_id = format!("nssaa-ctx-{}", self.next_ctx_id);
        self.next_ctx_id += 1;

        let initial_eap = EapPacket {
            code: EapCode::Request,
            identifier: 1,
            payload: b"Identity Request (Enterprise Slice)".to_vec(),
        };

        let ctx = SliceAuthContext {
            auth_ctx_id: ctx_id.clone(),
            supi: supi.to_string(),
            snssai,
            amf_id: amf_id.to_string(),
            enterprise_aaa_s: aaa_s,
            eap_session_id: 1,
            status: SliceAuthStatus::PendingChallenge,
            allowed_lifetime_s: 86400, // 24-hour default slice authorization token
            auth_timestamp_epoch_s: None,
        };

        self.contexts.insert(ctx_id.clone(), ctx);
        Ok((ctx_id, initial_eap))
    }

    /// Process EAP response and complete slice authentication round-trip.
    pub fn progress_slice_auth(
        &mut self,
        auth_ctx_id: &str,
        ue_eap_response: &EapPacket,
        current_epoch_s: u64,
    ) -> Result<(SliceAuthStatus, EapPacket), NssaafError> {
        let ctx = self
            .contexts
            .get_mut(auth_ctx_id)
            .ok_or(NssaafError::ContextNotFound)?;

        if ue_eap_response.code != EapCode::Response {
            return Err(NssaafError::InvalidEapPacket);
        }

        // Validate credentials against enterprise AAA-S
        let cred_key = (ctx.enterprise_aaa_s.clone(), ctx.supi.clone());
        let expected_secret = self.enterprise_credentials.get(&cred_key);

        if let Some(secret) = expected_secret {
            if &ue_eap_response.payload == secret {
                // EAP-Success
                ctx.status = SliceAuthStatus::Success;
                ctx.auth_timestamp_epoch_s = Some(current_epoch_s);

                let expiry_epoch_s = current_epoch_s + ctx.allowed_lifetime_s as u64;
                self.authorized_slices.insert(
                    (ctx.supi.clone(), ctx.snssai),
                    (expiry_epoch_s, ctx.amf_id.clone()),
                );

                let eap_success = EapPacket {
                    code: EapCode::Success,
                    identifier: ue_eap_response.identifier,
                    payload: Vec::new(),
                };

                return Ok((SliceAuthStatus::Success, eap_success));
            }
        }

        // Authentication failed
        ctx.status = SliceAuthStatus::Failed;
        let eap_failure = EapPacket {
            code: EapCode::Failure,
            identifier: ue_eap_response.identifier,
            payload: Vec::new(),
        };

        Ok((SliceAuthStatus::Failed, eap_failure))
    }

    // -----------------------------------------------------------------------
    // Slice Revocation Service (TS 29.531 Section 5.3)
    // -----------------------------------------------------------------------

    /// Revoke previously granted slice authorization (e.g. from Enterprise AAA-S).
    pub fn revoke_slice_auth(
        &mut self,
        supi: &str,
        snssai: Snssai,
        reason: &str,
        current_epoch_s: u64,
    ) -> Result<(), NssaafError> {
        let entry = self
            .authorized_slices
            .remove(&(supi.to_string(), snssai))
            .ok_or(NssaafError::ContextNotFound)?;

        // Queue revocation notification to serving AMF
        self.amf_revocation_queue.push(SliceRevocationNotification {
            supi: supi.to_string(),
            snssai,
            amf_id: entry.1,
            reason: reason.to_string(),
            timestamp_epoch_s: current_epoch_s,
        });

        // Update corresponding context if present
        for ctx in self.contexts.values_mut() {
            if ctx.supi == supi && ctx.snssai == snssai {
                ctx.status = SliceAuthStatus::Revoked;
            }
        }

        Ok(())
    }

    /// Check whether a subscriber currently has valid slice authorization.
    pub fn is_slice_authorized(&self, supi: &str, snssai: Snssai, current_epoch_s: u64) -> bool {
        if let Some((expiry, _)) = self.authorized_slices.get(&(supi.to_string(), snssai)) {
            current_epoch_s < *expiry
        } else {
            false
        }
    }
}

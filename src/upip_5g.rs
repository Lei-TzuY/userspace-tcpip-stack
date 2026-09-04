//! 5G User Plane Integrity Protection (UPIP) negotiation/state model.
//!
//! This module models UPIP policy, data-rate capability, PDCP COUNT state, and
//! replay-window metadata. It does **not** implement the 3GPP NIA1 (SNOW 3G),
//! NIA2 (AES-CMAC), or NIA3 (ZUC) integrity algorithms. Those algorithm values
//! are retained only so negotiation/configuration can represent them; selecting
//! any of them fails closed with [`UpipError::UnsupportedIntegrityAlgorithm`].
//!
//! NIA0 is the only executable algorithm today and provides no integrity
//! protection. A `Required` policy therefore also fails closed when paired with
//! NIA0. This keeps the API's security claims aligned with executable behavior.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// 5G UPIP Enums & Data Structures (TS 33.501 / TS 23.501 Section 5.10.3)
// ---------------------------------------------------------------------------

/// User Plane Integrity Protection Policy (TS 23.501 Section 5.10.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpIntegrityPolicy {
    Required,
    Preferred,
    NotNeeded,
}

/// Maximum Data Rate Supported for User Plane Integrity Protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaxDataRatePerUe {
    Rate64Kbps,
    FullRate,
}

/// 3GPP NR integrity-algorithm identifier used during negotiation.
///
/// Only `Nia0Null` is executable in this crate. NIA1/NIA2/NIA3 are represented
/// for protocol/state modelling but are rejected until conformant algorithms
/// are implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpIntegrityAlgorithm {
    Nia0Null,
    Nia1Snow3G,
    Nia2AesCmac,
    Nia3Zuc,
}

/// User Plane Security Context for an active PDU Session / Data Radio Bearer (DRB).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpSecurityContext {
    pub session_id: String,
    pub k_up_int: [u8; 16],
    pub algorithm: UpIntegrityAlgorithm,
    pub policy: UpIntegrityPolicy,
    pub max_rate: MaxDataRatePerUe,
    pub bearer_id: u8,
    pub uplink_count: u32,
    pub downlink_count: u32,
    pub replay_window_bottom: u32,
    pub replay_window_size: u32,
    pub packets_protected: u64,
    pub integrity_failures: u64,
}

/// UPIP error types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpipError {
    SessionNotFound,
    /// A negotiated 3GPP integrity algorithm has no conformant implementation.
    UnsupportedIntegrityAlgorithm {
        algorithm: UpIntegrityAlgorithm,
    },
    /// The requested policy requires integrity, but the selected executable
    /// algorithm (currently only NIA0) cannot provide it.
    IntegrityProtectionUnavailable,
    PacketTooShortForMaci,
    ReplayDetected {
        received_count: u32,
        window_bottom: u32,
    },
    IntegrityVerificationFailed {
        expected_maci: u32,
        observed_maci: u32,
    },
    DataRateLimitExceeded,
}

fn validate_security_choice(
    algorithm: UpIntegrityAlgorithm,
    policy: UpIntegrityPolicy,
) -> Result<(), UpipError> {
    match algorithm {
        UpIntegrityAlgorithm::Nia0Null => {
            if policy == UpIntegrityPolicy::Required {
                Err(UpipError::IntegrityProtectionUnavailable)
            } else {
                Ok(())
            }
        }
        UpIntegrityAlgorithm::Nia1Snow3G
        | UpIntegrityAlgorithm::Nia2AesCmac
        | UpIntegrityAlgorithm::Nia3Zuc => {
            Err(UpipError::UnsupportedIntegrityAlgorithm { algorithm })
        }
    }
}

// ---------------------------------------------------------------------------
// Top-Level 5G UPIP Engine
// ---------------------------------------------------------------------------

/// 5G User Plane Integrity Protection negotiation/state engine.
pub struct UpipEngine {
    pub engine_id: String,
    pub contexts: HashMap<String, UpSecurityContext>,
}

impl UpipEngine {
    /// Create a new 5G UPIP engine instance.
    pub fn new(engine_id: &str) -> Self {
        UpipEngine {
            engine_id: engine_id.to_string(),
            contexts: HashMap::new(),
        }
    }

    /// Provision a User Plane Security Context.
    ///
    /// Unsupported NIA algorithms and policy/algorithm combinations that cannot
    /// satisfy required integrity are rejected before state is installed.
    pub fn create_security_context(
        &mut self,
        session_id: &str,
        k_up_int: [u8; 16],
        algorithm: UpIntegrityAlgorithm,
        policy: UpIntegrityPolicy,
        max_rate: MaxDataRatePerUe,
        bearer_id: u8,
    ) -> Result<(), UpipError> {
        validate_security_choice(algorithm, policy)?;

        let ctx = UpSecurityContext {
            session_id: session_id.to_string(),
            k_up_int,
            algorithm,
            policy,
            max_rate,
            bearer_id,
            uplink_count: 0,
            downlink_count: 0,
            replay_window_bottom: 0,
            replay_window_size: 128,
            packets_protected: 0,
            integrity_failures: 0,
        };

        self.contexts.insert(session_id.to_string(), ctx);
        Ok(())
    }

    /// Process a downlink packet under the negotiated security context.
    ///
    /// NIA0 is pass-through. Unsupported or insufficient security choices fail
    /// closed, including contexts inserted directly through the public map.
    pub fn protect_downlink_packet(
        &mut self,
        session_id: &str,
        user_pdu: &[u8],
    ) -> Result<Vec<u8>, UpipError> {
        let ctx = self
            .contexts
            .get_mut(session_id)
            .ok_or(UpipError::SessionNotFound)?;

        validate_security_choice(ctx.algorithm, ctx.policy)?;
        Ok(user_pdu.to_vec())
    }

    /// Process an inbound uplink packet under the negotiated security context.
    ///
    /// NIA0 is pass-through. No MAC-I verification is claimed or performed
    /// until a conformant non-null NIA implementation exists.
    pub fn verify_uplink_packet(
        &mut self,
        session_id: &str,
        received_pdu: &[u8],
    ) -> Result<Vec<u8>, UpipError> {
        let ctx = self
            .contexts
            .get_mut(session_id)
            .ok_or(UpipError::SessionNotFound)?;

        validate_security_choice(ctx.algorithm, ctx.policy)?;
        Ok(received_pdu.to_vec())
    }

    /// Terminate security context.
    pub fn remove_security_context(&mut self, session_id: &str) -> Result<(), UpipError> {
        self.contexts
            .remove(session_id)
            .ok_or(UpipError::SessionNotFound)?;
        Ok(())
    }
}

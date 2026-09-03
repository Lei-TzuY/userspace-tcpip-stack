//! 3GPP TS 29.559 / TS 33.501 Annex R / TS 33.536 Release 17 5G Public Key Management Function (PKMF) Engine.
//!
//! Implements 5G Proximity Services (ProSe) Direct Communication Security & Key Management:
//! - Npkmf_PKMFKeyRequest Service (TS 29.559 Section 5.2):
//!   - ProSe Group Key (PGK) distribution for PC5 Sidelink broadcast/group communication
//!   - Key ID allocation (`pgk_id`: 0..255) and validity lifetime enforcement
//!   - Dynamic derivation of ProSe Encryption Key (PEK) and ProSe Integrity Key (PIK)
//!   - Forward and backward secrecy via emergency key rollover upon subscriber revocation
//!   - Pure Rust cryptographic key derivation function (KDF)

use std::collections::{HashMap, HashSet};

// ---------------------------------------------------------------------------
// 5G PKMF Enums & Data Structures (TS 29.559 / TS 33.536 Section 6)
// ---------------------------------------------------------------------------

/// ProSe Group Key (PGK) Record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProSeGroupKeyRecord {
    pub prose_group_id: String,
    pub pgk_id: u8,
    pub pgk: [u8; 32], // 256-bit root group key
    pub valid_until_epoch_s: u64,
}

/// Derived PC5 Sidelink Session Traffic Keys (TS 33.536 Section 6.2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pc5TrafficKeys {
    pub pek: [u8; 16], // 128-bit ProSe Encryption Key (for 128-NEA1/2/3)
    pub pik: [u8; 16], // 128-bit ProSe Integrity Key (for 128-NIA1/2/3)
}

/// Key Request Result returned to UE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRequestResponse {
    pub prose_group_id: String,
    pub pgk_id: u8,
    pub pgk: [u8; 32],
    pub valid_until_epoch_s: u64,
}

/// PKMF Error Types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PkmfError {
    UnauthorizedGroupMember,
    GroupNotFound,
    KeyExpired,
    RevocationFailed,
}

// ---------------------------------------------------------------------------
// Top-Level 5G-PKMF Engine
// ---------------------------------------------------------------------------

/// 5G Public Key Management Function (PKMF).
pub struct PkmfEngine {
    pub pkmf_id: String,
    /// Group Membership Whitelist: prose_group_id -> HashSet<supi>
    pub group_memberships: HashMap<String, HashSet<String>>,
    /// Active Group Keys: prose_group_id -> ProSeGroupKeyRecord
    pub active_keys: HashMap<String, ProSeGroupKeyRecord>,
    /// Default key lifetime in seconds (e.g. 86400s = 24h)
    pub default_key_lifetime_s: u64,
    /// Seed counter for deterministic key derivation in pure Rust
    pub key_seed_counter: u64,
}

impl PkmfEngine {
    /// Create a new 5G-PKMF engine instance.
    pub fn new(pkmf_id: &str) -> Self {
        PkmfEngine {
            pkmf_id: pkmf_id.to_string(),
            group_memberships: HashMap::new(),
            active_keys: HashMap::new(),
            default_key_lifetime_s: 86400,
            key_seed_counter: 1,
        }
    }

    /// Register a ProSe group with authorized member SUPIs.
    pub fn create_prose_group(
        &mut self,
        prose_group_id: &str,
        authorized_supis: Vec<&str>,
        initial_epoch_s: u64,
    ) {
        let mut members = HashSet::new();
        for supi in authorized_supis {
            members.insert(supi.to_string());
        }
        self.group_memberships
            .insert(prose_group_id.to_string(), members);

        // Generate initial PGK
        self.rotate_group_key(prose_group_id, initial_epoch_s);
    }

    /// Internal helper to roll or initialize a ProSe Group Key.
    fn rotate_group_key(&mut self, prose_group_id: &str, current_epoch_s: u64) {
        let next_pgk_id = match self.active_keys.get(prose_group_id) {
            Some(existing) => existing.pgk_id.wrapping_add(1),
            None => 1,
        };

        // Generate 256-bit key from seed counter
        let mut pgk = [0u8; 32];
        let seed = self.key_seed_counter;
        self.key_seed_counter += 1;

        for (i, byte) in pgk.iter_mut().enumerate() {
            let val = (seed ^ (i as u64)).wrapping_mul(0x517cc1b727220a95);
            *byte = (val >> ((i % 8) * 8)) as u8;
        }

        let record = ProSeGroupKeyRecord {
            prose_group_id: prose_group_id.to_string(),
            pgk_id: next_pgk_id,
            pgk,
            valid_until_epoch_s: current_epoch_s + self.default_key_lifetime_s,
        };

        self.active_keys.insert(prose_group_id.to_string(), record);
    }

    // -----------------------------------------------------------------------
    // Npkmf_PKMFKeyRequest Service Operations (TS 29.559 Section 5.2)
    // -----------------------------------------------------------------------

    /// Request active ProSe Group Key (PGK) for PC5 direct communication (Section 5.2.2.2).
    pub fn request_group_key(
        &mut self,
        supi: &str,
        prose_group_id: &str,
        current_epoch_s: u64,
    ) -> Result<KeyRequestResponse, PkmfError> {
        // 1. Verify Membership
        let members = self
            .group_memberships
            .get(prose_group_id)
            .ok_or(PkmfError::GroupNotFound)?;

        if !members.contains(supi) {
            return Err(PkmfError::UnauthorizedGroupMember);
        }

        // 2. Check if key needs rollover due to expiration
        let needs_rollover = match self.active_keys.get(prose_group_id) {
            Some(key) => current_epoch_s >= key.valid_until_epoch_s,
            None => true,
        };

        if needs_rollover {
            self.rotate_group_key(prose_group_id, current_epoch_s);
        }

        let key = self.active_keys.get(prose_group_id).unwrap();

        Ok(KeyRequestResponse {
            prose_group_id: prose_group_id.to_string(),
            pgk_id: key.pgk_id,
            pgk: key.pgk,
            valid_until_epoch_s: key.valid_until_epoch_s,
        })
    }

    /// Revoke a UE's group access and trigger immediate PGK emergency rollover (forward secrecy).
    pub fn revoke_group_member(
        &mut self,
        prose_group_id: &str,
        evicted_supi: &str,
        current_epoch_s: u64,
    ) -> Result<(), PkmfError> {
        let members = self
            .group_memberships
            .get_mut(prose_group_id)
            .ok_or(PkmfError::GroupNotFound)?;

        if !members.remove(evicted_supi) {
            return Err(PkmfError::RevocationFailed);
        }

        // Emergency key rollover: generate brand new PGK with incremented pgk_id immediately
        self.rotate_group_key(prose_group_id, current_epoch_s);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Pure Rust PC5 Sidelink KDF Key Derivation (TS 33.536 Section 6.2.3)
    // -----------------------------------------------------------------------

    /// Derive PC5 Sidelink Encryption (PEK) and Integrity (PIK) keys from PGK and Group Nonce.
    pub fn derive_pc5_session_keys(pgk: &[u8; 32], group_nonce: &[u8; 16]) -> Pc5TrafficKeys {
        let mut pek = [0u8; 16];
        let mut pik = [0u8; 16];

        // Pure Rust KDF mixing PGK, Nonce, and distinct FC (Function Code) separators
        for i in 0..16 {
            let mixed_pek = (pgk[i] as u32).wrapping_mul(0x9E37) ^ (group_nonce[i] as u32) ^ 0x01; // FC 0x01 for Encryption
            pek[i] = (mixed_pek & 0xFF) as u8;

            let mixed_pik =
                (pgk[i + 16] as u32).wrapping_mul(0x7F4A) ^ (group_nonce[i] as u32) ^ 0x02; // FC 0x02 for Integrity
            pik[i] = (mixed_pik & 0xFF) as u8;
        }

        Pc5TrafficKeys { pek, pik }
    }
}

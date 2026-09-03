//! 3GPP TS 29.525 / TS 23.501 Section 5.4.4.1 5G UE Radio Capability Management Function (UCMF) Engine.
//!
//! Implements 5G NR Radio Capability Management and Compression:
//! - Nucmf_UECapabilityManagement Service (TS 29.525 Section 5.2):
//!   - Radio Capability ID (RAC ID) Assignment (`assign_rac_id` - POST /assign-rac-id)
//!   - Radio Capability ID Resolution (`resolve_rac_id` - POST /rac-id-resolution)
//!   - Support for PLMN-Assigned and Manufacturer-Assigned RAC IDs
//!   - Cryptographic fingerprinting of multi-kilobyte 5G NR / E-UTRA ASN.1 capability blobs
//!   - Radio Capability Dictionary Management and deduplication

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// 5G UCMF Enums & Data Structures (TS 29.525 Section 6)
// ---------------------------------------------------------------------------

/// Type of Radio Capability ID (TS 23.501 Section 5.4.4.1a).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RacIdType {
    /// Assigned by the serving network operator UCMF.
    PlmnAssigned,
    /// Hardcoded by modem manufacturer / chipset vendor.
    ManufacturerAssigned,
}

/// Radio Access Technology Format for Capability Blobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RadioCapFormat {
    /// 5G New Radio (NR) ASN.1 capability blob.
    Nr,
    /// 4G E-UTRA ASN.1 capability blob.
    Eutra,
    /// Dual Connectivity (MR-DC / EN-DC) capability blob.
    MrDc,
}

/// Radio Capability ID (RAC ID).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RacId {
    pub rac_type: RacIdType,
    pub plmn_id: String, // MCC-MNC e.g. "208-95"
    pub id_string: String,
}

impl RacId {
    pub fn new_plmn_assigned(plmn_id: &str, unique_token: &str) -> Self {
        RacId {
            rac_type: RacIdType::PlmnAssigned,
            plmn_id: plmn_id.to_string(),
            id_string: format!("PLMN-{}-RAC-{}", plmn_id.replace('-', ""), unique_token),
        }
    }

    pub fn new_manufacturer_assigned(plmn_id: &str, manufacturer_rac: &str) -> Self {
        RacId {
            rac_type: RacIdType::ManufacturerAssigned,
            plmn_id: plmn_id.to_string(),
            id_string: manufacturer_rac.to_string(),
        }
    }
}

/// Stored Radio Capability Dictionary Entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RadioCapEntry {
    pub rac_id: RacId,
    pub cap_format: RadioCapFormat,
    pub capability_bytes: Vec<u8>,
    pub fingerprint_hex: String,
    pub creation_epoch_s: u64,
    pub associated_models: Vec<String>,
}

/// UCMF Error Types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UcmfError {
    RacIdNotFound,
    CapabilityNotFound,
    InvalidCapabilityPayload(&'static str),
    DuplicateManufacturerRacId,
}

// ---------------------------------------------------------------------------
// Top-Level UCMF Engine
// ---------------------------------------------------------------------------

/// 5G UE Radio Capability Management Function (UCMF).
pub struct UcmfEngine {
    pub ucmf_id: String,
    pub next_plmn_id_counter: u64,
    /// Primary dictionary: RacId -> RadioCapEntry
    pub dictionary: HashMap<RacId, RadioCapEntry>,
    /// Reverse index: fingerprint_hex -> RacId (for deduplication)
    pub fingerprint_to_rac: HashMap<String, RacId>,
}

impl UcmfEngine {
    /// Create a new UCMF engine instance.
    pub fn new(ucmf_id: &str) -> Self {
        UcmfEngine {
            ucmf_id: ucmf_id.to_string(),
            next_plmn_id_counter: 1,
            dictionary: HashMap::new(),
            fingerprint_to_rac: HashMap::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Nucmf_UECapabilityManagement Service Operations (TS 29.525 Section 5.2)
    // -----------------------------------------------------------------------

    /// Assign a Radio Capability ID for a raw radio capability blob (POST /assign-rac-id).
    /// If identical capability bytes already exist, returns the existing deduplicated RAC ID.
    pub fn assign_rac_id(
        &mut self,
        plmn_id: &str,
        cap_format: RadioCapFormat,
        capability_bytes: Vec<u8>,
        model_info: Option<&str>,
        current_epoch_s: u64,
    ) -> Result<RacId, UcmfError> {
        if capability_bytes.is_empty() {
            return Err(UcmfError::InvalidCapabilityPayload(
                "Capability bytes cannot be empty",
            ));
        }

        let fingerprint = compute_cap_fingerprint(&capability_bytes);

        // Deduplication: Return existing RAC ID if already registered
        if let Some(existing_rac) = self.fingerprint_to_rac.get(&fingerprint) {
            if let Some(entry) = self.dictionary.get_mut(existing_rac) {
                if let Some(model) = model_info {
                    if !entry.associated_models.iter().any(|m| m == model) {
                        entry.associated_models.push(model.to_string());
                    }
                }
            }
            return Ok(existing_rac.clone());
        }

        // Generate new PLMN-assigned RAC ID
        let token = format!("{:08x}", self.next_plmn_id_counter);
        self.next_plmn_id_counter += 1;

        let rac_id = RacId::new_plmn_assigned(plmn_id, &token);

        let mut models = Vec::new();
        if let Some(model) = model_info {
            models.push(model.to_string());
        }

        let entry = RadioCapEntry {
            rac_id: rac_id.clone(),
            cap_format,
            capability_bytes,
            fingerprint_hex: fingerprint.clone(),
            creation_epoch_s: current_epoch_s,
            associated_models: models,
        };

        self.fingerprint_to_rac.insert(fingerprint, rac_id.clone());
        self.dictionary.insert(rac_id.clone(), entry);

        Ok(rac_id)
    }

    /// Resolve a Radio Capability ID to the canonical raw capability bytes (POST /rac-id-resolution).
    pub fn resolve_rac_id(&self, rac_id: &RacId) -> Result<RadioCapEntry, UcmfError> {
        self.dictionary
            .get(rac_id)
            .cloned()
            .ok_or(UcmfError::RacIdNotFound)
    }

    /// Ingest a Manufacturer-assigned RAC ID into the dictionary.
    pub fn register_manufacturer_rac_id(
        &mut self,
        rac_id: RacId,
        cap_format: RadioCapFormat,
        capability_bytes: Vec<u8>,
        current_epoch_s: u64,
    ) -> Result<(), UcmfError> {
        if self.dictionary.contains_key(&rac_id) {
            return Err(UcmfError::DuplicateManufacturerRacId);
        }

        let fingerprint = compute_cap_fingerprint(&capability_bytes);
        let entry = RadioCapEntry {
            rac_id: rac_id.clone(),
            cap_format,
            capability_bytes,
            fingerprint_hex: fingerprint.clone(),
            creation_epoch_s: current_epoch_s,
            associated_models: vec!["Manufacturer Default".to_string()],
        };

        self.fingerprint_to_rac.insert(fingerprint, rac_id.clone());
        self.dictionary.insert(rac_id, entry);
        Ok(())
    }

    /// Delete a RAC ID from the dictionary.
    pub fn delete_dictionary_entry(&mut self, rac_id: &RacId) -> Result<(), UcmfError> {
        if let Some(entry) = self.dictionary.remove(rac_id) {
            self.fingerprint_to_rac.remove(&entry.fingerprint_hex);
            Ok(())
        } else {
            Err(UcmfError::RacIdNotFound)
        }
    }
}

// ---------------------------------------------------------------------------
// Capability Fingerprint Computation (Pure Rust 128-bit Hash)
// ---------------------------------------------------------------------------

fn compute_cap_fingerprint(bytes: &[u8]) -> String {
    // 128-bit FNV-1a / Murmur-like folding hash in pure Rust
    let mut h1: u64 = 0xcbf29ce484222325;
    let mut h2: u64 = 0x100000001b3;

    for (i, &b) in bytes.iter().enumerate() {
        if i % 2 == 0 {
            h1 ^= b as u64;
            h1 = h1.wrapping_mul(0x100000001b3);
        } else {
            h2 ^= b as u64;
            h2 = h2.wrapping_mul(0xcbf29ce484222325);
        }
    }

    format!("{:016x}{:016x}", h1, h2)
}

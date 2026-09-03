//! 3GPP TS 29.511 / TS 23.501 5G Equipment Identity Register (5G-EIR) Engine.
//!
//! Implements the 5G-EIR network function and `N5g-eir_EquipmentIdentityCheck` service:
//! - PEI (Permanent Equipment Identifier: IMEI / IMEISV) format parsing and validation
//! - Luhn check-digit verification algorithm (TS 23.003 Section 6.2)
//! - Equipment Status classification: `Whitelisted`, `Blacklisted`, `Greylisted` (TS 29.511 Section 6.1.6.3.3)
//! - TAC (Type Allocation Code) manufacturer / model range filtering
//! - Anti-spoofing and cloned device detection (concurrent SUPI / PEI mismatch)
//! - Timed Greylist entries with automatic expiration

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// 5G-EIR Enums & Data Structures (TS 29.511 Section 6)
// ---------------------------------------------------------------------------

/// 3GPP TS 29.511 Equipment Status result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EquipmentStatus {
    Whitelisted,
    Blacklisted,
    Greylisted,
}

impl EquipmentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            EquipmentStatus::Whitelisted => "WHITELISTED",
            EquipmentStatus::Blacklisted => "BLACKLISTED",
            EquipmentStatus::Greylisted => "GREYLISTED",
        }
    }
}

/// Parsed 5G Permanent Equipment Identifier (PEI: IMEI or IMEISV).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pei {
    pub raw: String,
    pub tac: String,       // Type Allocation Code (8 digits)
    pub snr: String,       // Serial Number (6 digits)
    pub cd_or_svn: String, // Check Digit (1 digit for IMEI) or SVN (2 digits for IMEISV)
    pub is_imeisv: bool,
}

impl Pei {
    /// Parse and validate a PEI string (15-digit IMEI or 16-digit IMEISV).
    pub fn parse(s: &str) -> Result<Self, EirError> {
        let cleaned: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
        if cleaned.len() != 15 && cleaned.len() != 16 {
            return Err(EirError::InvalidPeiFormat("PEI must be 15 or 16 digits"));
        }

        let is_imeisv = cleaned.len() == 16;
        let tac = cleaned[0..8].to_string();
        let snr = cleaned[8..14].to_string();
        let cd_or_svn = if is_imeisv {
            cleaned[14..16].to_string()
        } else {
            cleaned[14..15].to_string()
        };

        // If standard 15-digit IMEI, verify Luhn checksum
        if !is_imeisv && !validate_luhn(&cleaned) {
            return Err(EirError::LuhnChecksumFailed);
        }

        Ok(Pei {
            raw: cleaned,
            tac,
            snr,
            cd_or_svn,
            is_imeisv,
        })
    }
}

/// Record for a greylisted equipment under observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GreylistRecord {
    pub reason: String,
    pub expires_at_epoch_s: u64,
}

/// Request for N5g-eir_EquipmentIdentityCheck service (GET /equipment-status).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EquipmentCheckRequest {
    pub pei: String,
    pub supi: Option<String>,
    pub tracking_area_code: Option<u32>,
    pub timestamp_epoch_s: u64,
}

/// Response returned by 5G-EIR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EquipmentCheckResponse {
    pub status: EquipmentStatus,
    pub pei: String,
    pub reason: Option<String>,
}

/// Active registration record tracking a PEI's last seen presence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeiPresenceRecord {
    pub supi: String,
    pub tac_code: u32,
    pub timestamp_s: u64,
}

/// 5G-EIR Error types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EirError {
    InvalidPeiFormat(&'static str),
    LuhnChecksumFailed,
}

// ---------------------------------------------------------------------------
// 5G-EIR Engine
// ---------------------------------------------------------------------------

/// 5G Equipment Identity Register (5G-EIR) Engine.
pub struct EirEngine {
    pub eir_id: String,
    /// Explicitly blacklisted PEIs (IMEI / IMEISV) -> Reason
    pub blacklisted_peis: HashMap<String, String>,
    /// Explicitly blacklisted TACs (e.g. fraudulent phone batches) -> Reason
    pub blacklisted_tacs: HashMap<String, String>,
    /// Greylisted PEIs -> GreylistRecord
    pub greylisted_peis: HashMap<String, GreylistRecord>,
    /// Explicitly whitelisted PEIs (overrides TAC blacklists if authorized)
    pub whitelisted_peis: HashMap<String, String>,
    /// Cloned device detection: PEI -> PeiPresenceRecord
    pub active_presences: HashMap<String, PeiPresenceRecord>,
}

impl EirEngine {
    /// Create a new 5G-EIR instance.
    pub fn new(eir_id: &str) -> Self {
        EirEngine {
            eir_id: eir_id.to_string(),
            blacklisted_peis: HashMap::new(),
            blacklisted_tacs: HashMap::new(),
            greylisted_peis: HashMap::new(),
            whitelisted_peis: HashMap::new(),
            active_presences: HashMap::new(),
        }
    }

    /// Add a PEI to the blacklist (e.g. reported stolen).
    pub fn blacklist_pei(&mut self, pei_str: &str, reason: &str) -> Result<(), EirError> {
        let pei = Pei::parse(pei_str)?;
        self.blacklisted_peis.insert(pei.raw, reason.to_string());
        Ok(())
    }

    /// Add a TAC (8 digits) to the blacklist (e.g. vulnerable hardware).
    pub fn blacklist_tac(&mut self, tac: &str, reason: &str) {
        self.blacklisted_tacs
            .insert(tac.to_string(), reason.to_string());
    }

    /// Add a PEI to the greylist with a validity expiration.
    pub fn greylist_pei(
        &mut self,
        pei_str: &str,
        reason: &str,
        expires_at_epoch_s: u64,
    ) -> Result<(), EirError> {
        let pei = Pei::parse(pei_str)?;
        self.greylisted_peis.insert(
            pei.raw,
            GreylistRecord {
                reason: reason.to_string(),
                expires_at_epoch_s,
            },
        );
        Ok(())
    }

    /// Add an explicit whitelist entry.
    pub fn whitelist_pei(&mut self, pei_str: &str, note: &str) -> Result<(), EirError> {
        let pei = Pei::parse(pei_str)?;
        self.whitelisted_peis.insert(pei.raw, note.to_string());
        Ok(())
    }

    /// N5g-eir_EquipmentIdentityCheck operation (TS 29.511 Section 5.2.2.2).
    pub fn check_equipment_status(
        &mut self,
        req: &EquipmentCheckRequest,
    ) -> Result<EquipmentCheckResponse, EirError> {
        let pei = Pei::parse(&req.pei)?;

        // 1. Check explicit whitelist
        if let Some(note) = self.whitelisted_peis.get(&pei.raw) {
            return Ok(EquipmentCheckResponse {
                status: EquipmentStatus::Whitelisted,
                pei: pei.raw,
                reason: Some(note.clone()),
            });
        }

        // 2. Check PEI blacklist
        if let Some(reason) = self.blacklisted_peis.get(&pei.raw) {
            return Ok(EquipmentCheckResponse {
                status: EquipmentStatus::Blacklisted,
                pei: pei.raw,
                reason: Some(reason.clone()),
            });
        }

        // 3. Check TAC blacklist
        if let Some(reason) = self.blacklisted_tacs.get(&pei.tac) {
            return Ok(EquipmentCheckResponse {
                status: EquipmentStatus::Blacklisted,
                pei: pei.raw,
                reason: Some(format!("TAC {} Blacklisted: {}", pei.tac, reason)),
            });
        }

        // 4. Check Greylist
        if let Some(record) = self.greylisted_peis.get(&pei.raw) {
            if req.timestamp_epoch_s <= record.expires_at_epoch_s {
                return Ok(EquipmentCheckResponse {
                    status: EquipmentStatus::Greylisted,
                    pei: pei.raw,
                    reason: Some(record.reason.clone()),
                });
            }
        }

        // 5. Anti-Spoofing / Cloned PEI Detection:
        // If the same PEI is observed with a DIFFERENT SUPI in a different tracking area within 60s
        if let (Some(supi), Some(tac_code)) = (&req.supi, req.tracking_area_code) {
            if let Some(prev) = self.active_presences.get(&pei.raw) {
                let dt = req.timestamp_epoch_s.saturating_sub(prev.timestamp_s);
                if dt < 60 && prev.supi != *supi && prev.tac_code != tac_code {
                    // Possible cloned IMEI attack!
                    return Ok(EquipmentCheckResponse {
                        status: EquipmentStatus::Blacklisted,
                        pei: pei.raw,
                        reason: Some(format!(
                            "Cloned PEI anomaly: observed with SUPI {} and {} concurrently",
                            prev.supi, supi
                        )),
                    });
                }
            }

            self.active_presences.insert(
                pei.raw.clone(),
                PeiPresenceRecord {
                    supi: supi.clone(),
                    tac_code,
                    timestamp_s: req.timestamp_epoch_s,
                },
            );
        }

        // Default: Whitelisted
        Ok(EquipmentCheckResponse {
            status: EquipmentStatus::Whitelisted,
            pei: pei.raw,
            reason: None,
        })
    }
}

// ---------------------------------------------------------------------------
// Luhn Algorithm (Mod 10) Verification (TS 23.003 Section 6.2)
// ---------------------------------------------------------------------------

/// Computes Luhn algorithm checksum.
pub fn validate_luhn(digits: &str) -> bool {
    let mut sum = 0;
    let len = digits.len();

    for (i, c) in digits.chars().enumerate() {
        let d = match c.to_digit(10) {
            Some(val) => val,
            None => return false,
        };

        // For 15 digits: odd positions (from right, 0-indexed) are doubled
        let is_even_from_right = (len - 1 - i) % 2 == 1;
        if is_even_from_right {
            let doubled = d * 2;
            sum += (doubled / 10) + (doubled % 10);
        } else {
            sum += d;
        }
    }

    sum % 10 == 0
}

/// Helper to compute check digit for 14-digit IMEI body.
pub fn calculate_luhn_check_digit(fourteen_digits: &str) -> Option<u8> {
    if fourteen_digits.len() != 14 {
        return None;
    }
    let mut sum = 0;
    for (i, c) in fourteen_digits.chars().enumerate() {
        let d = c.to_digit(10)?;
        // In 15-digit IMEI, 0-indexed from left: odd indices (1, 3, 5, 7, 9, 11, 13) are doubled
        if i % 2 == 1 {
            let doubled = d * 2;
            sum += (doubled / 10) + (doubled % 10);
        } else {
            sum += d;
        }
    }

    let check = (10 - (sum % 10)) % 10;
    Some(check as u8)
}

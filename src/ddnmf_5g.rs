//! 3GPP TS 29.579 / TS 23.304 Release 17 5G Direct Discovery Name Management Function (5G-DDNMF) Engine.
//!
//! Implements 5G Proximity Services (ProSe) Direct Discovery Name Management:
//! - N5g-ddnmf_Discovery Service (TS 29.579 Section 5.2):
//!   - Announce Authorization & ProSe Application Code (PAC) allocation (`authorize_announce`)
//!   - Monitor Authorization & Discovery Filter allocation (`authorize_monitor`)
//!   - Match Report evaluation (`match_report` - PC5 Sidelink code resolution to ProSe App ID)
//!   - Ephemeral privacy token rotation preventing physical tracking over PC5 Sidelink
//!   - Time-to-Live (TTL) expiration and immediate announcement revocation

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// 5G ProSe Enums & Data Structures (TS 29.579 Section 6 / TS 23.003)
// ---------------------------------------------------------------------------

/// ProSe Discovery Role (TS 23.304 Section 5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProSeDiscoveryRole {
    Announcing,
    Monitoring,
}

/// ProSe Application Code (PAC - TS 23.003 Section 24.3).
/// 184-bit code transmitted over PC5 Sidelink containing PLMN and ephemeral token.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProSeAppCode {
    pub plmn_id: String, // e.g. "208-95"
    pub app_prefix: String,
    pub ephemeral_token: String,
}

impl ProSeAppCode {
    pub fn to_hex_string(&self) -> String {
        format!(
            "PAC-{}-{}-{}",
            self.plmn_id.replace('-', ""),
            self.app_prefix,
            self.ephemeral_token
        )
    }
}

/// Announcement Authorization Record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnouncementRecord {
    pub prose_app_id: String,
    pub announcing_supi: String,
    pub prose_app_code: ProSeAppCode,
    pub valid_until_epoch_s: u64,
}

/// Monitoring Authorization Record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorRecord {
    pub prose_app_id: String,
    pub monitoring_supi: String,
    pub valid_until_epoch_s: u64,
}

/// Match Report Response returned to Monitoring UE (TS 29.579 Section 5.2.2.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchReportResult {
    pub prose_app_id: String,
    pub announcing_supi: String,
    pub validity_time_remaining_s: u64,
}

/// 5G-DDNMF Error Types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DdnmfError {
    UnauthorizedAppId,
    UnauthorizedMonitor,
    ProSeCodeNotFound,
    ProSeCodeExpired,
    RevocationFailed,
}

// ---------------------------------------------------------------------------
// Top-Level 5G-DDNMF Engine
// ---------------------------------------------------------------------------

/// 5G Direct Discovery Name Management Function (5G-DDNMF).
pub struct DdnmfEngine {
    pub ddnmf_id: String,
    pub plmn_id: String,
    pub next_token_counter: u64,
    /// Active Announcements: code_hex -> AnnouncementRecord
    pub active_announcements: HashMap<String, AnnouncementRecord>,
    /// Authorized Monitors: (prose_app_id, monitoring_supi) -> MonitorRecord
    pub authorized_monitors: HashMap<(String, String), MonitorRecord>,
    /// Allowed ProSe Application Whitelist per SUPI: supi -> Vec<prose_app_id>
    pub supi_permissions: HashMap<String, Vec<String>>,
}

impl DdnmfEngine {
    /// Create a new 5G-DDNMF engine.
    pub fn new(ddnmf_id: &str, plmn_id: &str) -> Self {
        DdnmfEngine {
            ddnmf_id: ddnmf_id.to_string(),
            plmn_id: plmn_id.to_string(),
            next_token_counter: 1,
            active_announcements: HashMap::new(),
            authorized_monitors: HashMap::new(),
            supi_permissions: HashMap::new(),
        }
    }

    /// Grant permission to a SUPI for a specific ProSe Application ID.
    pub fn grant_permission(&mut self, supi: &str, prose_app_id: &str) {
        self.supi_permissions
            .entry(supi.to_string())
            .or_default()
            .push(prose_app_id.to_string());
    }

    // -----------------------------------------------------------------------
    // N5g-ddnmf_Discovery Service Operations (TS 29.579 Section 5.2)
    // -----------------------------------------------------------------------

    /// Authorize Announcement and allocate a fresh ProSe App Code (TS 29.579 Section 5.2.2.2).
    pub fn authorize_announce(
        &mut self,
        announcing_supi: &str,
        prose_app_id: &str,
        validity_duration_s: u64,
        current_epoch_s: u64,
    ) -> Result<ProSeAppCode, DdnmfError> {
        // 1. Verify Authorization
        let allowed = self
            .supi_permissions
            .get(announcing_supi)
            .map(|apps| apps.iter().any(|a| a == prose_app_id))
            .unwrap_or(false);

        if !allowed {
            return Err(DdnmfError::UnauthorizedAppId);
        }

        // 2. Generate Ephemeral ProSe App Code
        let token_hex = format!("{:016x}", self.next_token_counter);
        self.next_token_counter += 1;

        let prefix = prose_app_id
            .split('.')
            .next()
            .unwrap_or("app")
            .to_uppercase();

        let pac = ProSeAppCode {
            plmn_id: self.plmn_id.clone(),
            app_prefix: prefix,
            ephemeral_token: token_hex,
        };

        let valid_until = current_epoch_s + validity_duration_s;
        let record = AnnouncementRecord {
            prose_app_id: prose_app_id.to_string(),
            announcing_supi: announcing_supi.to_string(),
            prose_app_code: pac.clone(),
            valid_until_epoch_s: valid_until,
        };

        self.active_announcements
            .insert(pac.to_hex_string(), record);
        Ok(pac)
    }

    /// Authorize Monitoring for a target ProSe Application ID (TS 29.579 Section 5.2.2.3).
    pub fn authorize_monitor(
        &mut self,
        monitoring_supi: &str,
        prose_app_id: &str,
        validity_duration_s: u64,
        current_epoch_s: u64,
    ) -> Result<(), DdnmfError> {
        let allowed = self
            .supi_permissions
            .get(monitoring_supi)
            .map(|apps| apps.iter().any(|a| a == prose_app_id))
            .unwrap_or(false);

        if !allowed {
            return Err(DdnmfError::UnauthorizedAppId);
        }

        let record = MonitorRecord {
            prose_app_id: prose_app_id.to_string(),
            monitoring_supi: monitoring_supi.to_string(),
            valid_until_epoch_s: current_epoch_s + validity_duration_s,
        };

        self.authorized_monitors.insert(
            (prose_app_id.to_string(), monitoring_supi.to_string()),
            record,
        );

        Ok(())
    }

    /// Process PC5 Sidelink Match Report from Monitoring UE (TS 29.579 Section 5.2.2.4).
    pub fn match_report(
        &self,
        monitoring_supi: &str,
        prose_app_code_hex: &str,
        current_epoch_s: u64,
    ) -> Result<MatchReportResult, DdnmfError> {
        // 1. Locate Announcement Record
        let ann = self
            .active_announcements
            .get(prose_app_code_hex)
            .ok_or(DdnmfError::ProSeCodeNotFound)?;

        // 2. Check Expiry
        if current_epoch_s >= ann.valid_until_epoch_s {
            return Err(DdnmfError::ProSeCodeExpired);
        }

        // 3. Verify Monitoring Authorization
        let mon = self
            .authorized_monitors
            .get(&(ann.prose_app_id.clone(), monitoring_supi.to_string()))
            .ok_or(DdnmfError::UnauthorizedMonitor)?;

        if current_epoch_s >= mon.valid_until_epoch_s {
            return Err(DdnmfError::UnauthorizedMonitor);
        }

        let remaining = ann.valid_until_epoch_s - current_epoch_s;

        Ok(MatchReportResult {
            prose_app_id: ann.prose_app_id.clone(),
            announcing_supi: ann.announcing_supi.clone(),
            validity_time_remaining_s: remaining,
        })
    }

    /// Revoke an active announcement code immediately.
    pub fn revoke_announcement(&mut self, prose_app_code_hex: &str) -> Result<(), DdnmfError> {
        self.active_announcements
            .remove(prose_app_code_hex)
            .map(|_| ())
            .ok_or(DdnmfError::RevocationFailed)
    }
}

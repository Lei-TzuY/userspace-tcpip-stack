//! 3GPP Release 18/19 5G-Advanced PDCCH Power Saving Engine:
//! Search Space Set Group Switching (SSGS) & PDCCH Monitoring Skipping.
//!
//! Standards Reference:
//! - 3GPP TS 38.213 Rel-18 §10.4: Search space set group switching and PDCCH monitoring skipping.
//! - 3GPP TS 38.331 Rel-18: `SearchSpaceSwitchConfig`, `searchSpaceSwitchTimer-r16`, `skippingDurationList`.
//! - 3GPP TS 38.212 Rel-18 §7.3.1.2: DCI formats 0_1 / 1_1 with SSG switching & skipping fields.
//! - 3GPP TS 38.213 Rel-18 §10.1: UE PDCCH blind decoding candidate allocation.
//!
//! Features:
//! 1. Search Space Set Group Switching (SSGS):
//!    - Group 0 (Default / Sparse monitoring for low-traffic and power saving)
//!    - Group 1 (Dense / High activity monitoring for burst throughput)
//!    - Group 2 (Optional secondary group for specialized traffic such as XR / URLLC)
//! 2. DCI-driven explicit switching with configurable switching delay $P_{\text{switch}}$ ($n + P_{\text{switch}}$).
//! 3. Autonomous fallback timer (`searchSpaceSwitchTimer`): UE autonomously falls back from Group 1
//!    to default Group 0 when no DCI is received for the timer duration.
//! 4. PDCCH Monitoring Skipping: UE skips PDCCH monitoring for $K_{\text{skip}}$ slots ($n + P_{\text{skip}}$)
//!    while exempting Common Search Spaces (CSS) to preserve vital system information, paging, and RACH reception.
//! 5. Comprehensive power saving telemetry: blind decode counts and power reduction ratio tracking.
//! 6. Binary wire framing (`NrSsgsWirePdu`) with magic `0x53534753` ("SSGS") and CRC-16 CCITT validation.

use std::fmt;

// ---------------------------------------------------------------------------
// Constants & CRC-16
// ---------------------------------------------------------------------------

/// Magic bytes for SSGS Wire PDU: "SSGS" (0x53534753).
pub const SSGS_WIRE_MAGIC: u32 = 0x53534753;

/// Standard CRC-16 CCITT polynomial.
pub const CRC16_CCITT_POLY: u16 = 0x1021;

/// Maximum number of search space sets per BWP in 5G NR.
pub const MAX_SEARCH_SPACES: usize = 40;

/// Errors encountered during PDCCH power saving operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PdcchPowerSavingError {
    InvalidGroup(u8),
    InvalidSkippingIndex(usize),
    SearchSpaceNotFound(u8),
    DuplicateSearchSpace(u8),
    MaxSearchSpacesExceeded,
    InvalidWireMagic(u32),
    WirePayloadTooShort { needed: usize, found: usize },
    WireCrcMismatch { expected: u16, computed: u16 },
}

impl fmt::Display for PdcchPowerSavingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidGroup(g) => write!(f, "Invalid search space set group ID: {}", g),
            Self::InvalidSkippingIndex(idx) => {
                write!(f, "Invalid skipping duration index: {}", idx)
            }
            Self::SearchSpaceNotFound(id) => write!(f, "Search space set {} not found", id),
            Self::DuplicateSearchSpace(id) => write!(f, "Duplicate search space set {}", id),
            Self::MaxSearchSpacesExceeded => {
                write!(f, "Exceeded maximum search spaces ({})", MAX_SEARCH_SPACES)
            }
            Self::InvalidWireMagic(m) => write!(f, "Invalid wire magic: 0x{:08X}", m),
            Self::WirePayloadTooShort { needed, found } => {
                write!(
                    f,
                    "Wire payload too short: needed {} bytes, found {}",
                    needed, found
                )
            }
            Self::WireCrcMismatch { expected, computed } => {
                write!(
                    f,
                    "Wire CRC mismatch: expected 0x{:04X}, computed 0x{:04X}",
                    expected, computed
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Enums & Structs (TS 38.213 §10.4 / TS 38.331)
// ---------------------------------------------------------------------------

/// Search Space Set Group (TS 38.213 §10.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SearchSpaceGroup {
    /// Group 0: Default / Power-saving / Sparse monitoring group.
    Group0 = 0,
    /// Group 1: Dense / High-throughput monitoring group.
    Group1 = 1,
    /// Group 2: Secondary / Specialized monitoring group.
    Group2 = 2,
}

impl SearchSpaceGroup {
    pub fn from_u8(val: u8) -> Result<Self, PdcchPowerSavingError> {
        match val {
            0 => Ok(Self::Group0),
            1 => Ok(Self::Group1),
            2 => Ok(Self::Group2),
            other => Err(PdcchPowerSavingError::InvalidGroup(other)),
        }
    }
}

/// Type of Search Space (TS 38.213 §10.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchSpaceType {
    /// Common Search Space (e.g. Type0/0A/1/2/3 CSS).
    /// Always preserved during PDCCH skipping to prevent missing system alerts/paging/RACH.
    Common,
    /// UE-specific Search Space (USS). Subject to skipping and group switching.
    UeSpecific,
}

/// Configuration of a single Search Space Set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchSpaceConfig {
    pub id: u8,
    pub ss_type: SearchSpaceType,
    pub group_memberships: Vec<SearchSpaceGroup>,
    pub periodicity_slots: u16,
    pub offset_slots: u16,
    pub num_candidates: u16, // Number of blind decode candidates across aggregation levels
}

/// Configuration for PDCCH Power Saving (TS 38.331 `SearchSpaceSwitchConfig`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdcchPowerSavingConfig {
    /// `searchSpaceSwitchTimer` in slots. If UE is in Group 1 and timer expires, falls back to Group 0.
    pub switch_timer_slots: Option<u16>,
    /// Delay in slots for SSG switching ($P_{\text{switch}}$).
    pub p_switch_slots: u8,
    /// Delay in slots for PDCCH monitoring skipping ($P_{\text{skip}}$).
    pub p_skip_slots: u8,
    /// Configured skipping duration options ($K_{\text{skip}}$ in slots).
    pub skipping_durations: Vec<u8>,
}

impl Default for PdcchPowerSavingConfig {
    fn default() -> Self {
        Self {
            switch_timer_slots: Some(10), // Default 10 slots
            p_switch_slots: 1,            // 1 slot delay
            p_skip_slots: 1,              // 1 slot delay
            skipping_durations: vec![1, 2, 4, 8],
        }
    }
}

/// Result of evaluating PDCCH monitoring for a specific slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotMonitoringDecision {
    pub slot_idx: u64,
    pub active_group: SearchSpaceGroup,
    pub is_skipping_uss: bool,
    pub monitored_search_spaces: Vec<u8>, // Search Space IDs to monitor
    pub total_candidates: u16,
    pub max_possible_candidates: u16,
    pub power_saving_percentage: u8, // 0..100%
}

// ---------------------------------------------------------------------------
// PDCCH Power Saving Engine (TS 38.213 §10.4)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PdcchPowerSavingEngine {
    config: PdcchPowerSavingConfig,
    search_spaces: Vec<SearchSpaceConfig>,
    active_group: SearchSpaceGroup,
    pending_switch: Option<(SearchSpaceGroup, u8)>, // (target_group, remaining_delay_slots)
    active_timer: Option<u16>,                      // Remaining switch timer countdown
    skip_remaining_slots: u8,
    pending_skip: Option<(u8, u8)>, // (skip_duration, remaining_delay_slots)
}

impl PdcchPowerSavingEngine {
    pub fn new(config: PdcchPowerSavingConfig) -> Self {
        Self {
            config,
            search_spaces: Vec::new(),
            active_group: SearchSpaceGroup::Group0, // Per 3GPP spec, UE starts in default Group 0
            pending_switch: None,
            active_timer: None,
            skip_remaining_slots: 0,
            pending_skip: None,
        }
    }

    /// Adds a search space set configuration.
    pub fn add_search_space(&mut self, ss: SearchSpaceConfig) -> Result<(), PdcchPowerSavingError> {
        if self.search_spaces.len() >= MAX_SEARCH_SPACES {
            return Err(PdcchPowerSavingError::MaxSearchSpacesExceeded);
        }
        if self.search_spaces.iter().any(|s| s.id == ss.id) {
            return Err(PdcchPowerSavingError::DuplicateSearchSpace(ss.id));
        }
        self.search_spaces.push(ss);
        Ok(())
    }

    /// Current active search space set group.
    pub fn active_group(&self) -> SearchSpaceGroup {
        self.active_group
    }

    /// Remaining `searchSpaceSwitchTimer` in slots, if active.
    pub fn remaining_timer(&self) -> Option<u16> {
        self.active_timer
    }

    /// Remaining PDCCH skipping duration in slots.
    pub fn remaining_skipping_slots(&self) -> u8 {
        self.skip_remaining_slots
    }

    /// Processes a DCI reception indicating SSG switching and/or PDCCH skipping (TS 38.213 §10.4).
    pub fn handle_dci(
        &mut self,
        target_group: Option<SearchSpaceGroup>,
        skip_duration_idx: Option<usize>,
    ) -> Result<(), PdcchPowerSavingError> {
        // 1. Handle DCI Search Space Group Switching indication
        if let Some(group) = target_group {
            if self.config.p_switch_slots == 0 {
                self.apply_group_switch(group);
            } else {
                self.pending_switch = Some((group, self.config.p_switch_slots));
            }
        } else if self.active_group == SearchSpaceGroup::Group1 {
            // Any DCI received while in Group 1 restarts the switch timer (TS 38.213 §10.4)
            self.active_timer = self.config.switch_timer_slots;
        }

        // 2. Handle PDCCH Monitoring Skipping indication
        if let Some(idx) = skip_duration_idx {
            if idx >= self.config.skipping_durations.len() {
                return Err(PdcchPowerSavingError::InvalidSkippingIndex(idx));
            }
            let duration = self.config.skipping_durations[idx];
            if self.config.p_skip_slots == 0 {
                self.skip_remaining_slots = duration;
            } else {
                self.pending_skip = Some((duration, self.config.p_skip_slots));
            }
        }

        Ok(())
    }

    fn apply_group_switch(&mut self, group: SearchSpaceGroup) {
        self.active_group = group;
        if group == SearchSpaceGroup::Group1 {
            // Start the switch timer
            self.active_timer = self.config.switch_timer_slots;
        } else {
            self.active_timer = None;
        }
    }

    /// Advances simulation by 1 slot and calculates the monitoring decision for the new slot.
    pub fn advance_slot(&mut self, slot_idx: u64) -> SlotMonitoringDecision {
        // 1. Process pending group switch delay
        if let Some((target_group, remaining)) = self.pending_switch {
            if remaining == 0 {
                self.apply_group_switch(target_group);
                self.pending_switch = None;
            } else {
                self.pending_switch = Some((target_group, remaining - 1));
            }
        }

        // 2. Process pending skipping delay
        if let Some((duration, remaining)) = self.pending_skip {
            if remaining == 0 {
                self.skip_remaining_slots = duration;
                self.pending_skip = None;
            } else {
                self.pending_skip = Some((duration, remaining - 1));
            }
        }

        // 3. Process searchSpaceSwitchTimer countdown (TS 38.213 §10.4)
        if self.active_group == SearchSpaceGroup::Group1 {
            if let Some(timer) = self.active_timer {
                if timer <= 1 {
                    // Timer expired: autonomously fall back to default Group 0!
                    self.active_group = SearchSpaceGroup::Group0;
                    self.active_timer = None;
                } else {
                    self.active_timer = Some(timer - 1);
                }
            }
        }

        // 4. Check if skipping is active for this slot
        let is_skipping_uss = self.skip_remaining_slots > 0;
        if self.skip_remaining_slots > 0 {
            self.skip_remaining_slots -= 1;
        }

        // 5. Determine which search space sets must be monitored
        let mut monitored = Vec::new();
        let mut total_candidates = 0u16;
        let mut max_possible_candidates = 0u16;

        for ss in &self.search_spaces {
            // Check periodicity alignment: (slot - offset) % periodicity == 0
            let slot_offset = (slot_idx + ss.periodicity_slots as u64
                - (ss.offset_slots as u64 % ss.periodicity_slots as u64))
                % ss.periodicity_slots as u64;
            let is_slot_aligned = slot_offset == 0;

            if is_slot_aligned {
                max_possible_candidates += ss.num_candidates;
            }

            match ss.ss_type {
                SearchSpaceType::Common => {
                    // Common Search Spaces (CSS) are ALWAYS monitored when aligned, even during skipping!
                    if is_slot_aligned {
                        monitored.push(ss.id);
                        total_candidates += ss.num_candidates;
                    }
                }
                SearchSpaceType::UeSpecific => {
                    // USS is skipped during active skipping duration
                    if !is_skipping_uss && is_slot_aligned {
                        // Check if SS belongs to current active group
                        if ss.group_memberships.contains(&self.active_group) {
                            monitored.push(ss.id);
                            total_candidates += ss.num_candidates;
                        }
                    }
                }
            }
        }

        // Calculate power saving percentage
        let power_saving_percentage = if max_possible_candidates == 0 {
            100
        } else if total_candidates >= max_possible_candidates {
            0
        } else {
            let saved = max_possible_candidates - total_candidates;
            ((saved as u32 * 100) / (max_possible_candidates as u32)) as u8
        };

        SlotMonitoringDecision {
            slot_idx,
            active_group: self.active_group,
            is_skipping_uss,
            monitored_search_spaces: monitored,
            total_candidates,
            max_possible_candidates,
            power_saving_percentage,
        }
    }
}

// ---------------------------------------------------------------------------
// CRC-16 CCITT & Binary Wire Framing (`NrSsgsWirePdu`)
// ---------------------------------------------------------------------------

pub fn compute_crc16(data: &[u8]) -> u16 {
    let mut crc = 0xFFFFu16;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            if (crc & 0x8000) != 0 {
                crc = (crc << 1) ^ CRC16_CCITT_POLY;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// Binary Wire PDU for SSGS Telemetry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NrSsgsWirePdu {
    pub sfn: u16,
    pub slot: u16,
    pub active_group: u8,
    pub skip_remaining_slots: u8,
    pub switch_timer_val: u16,
    pub total_candidates: u16,
    pub max_candidates: u16,
}

impl NrSsgsWirePdu {
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(18);
        buf.extend_from_slice(&SSGS_WIRE_MAGIC.to_be_bytes()); // 4 bytes
        buf.extend_from_slice(&self.sfn.to_be_bytes()); // 2 bytes
        buf.extend_from_slice(&self.slot.to_be_bytes()); // 2 bytes
        buf.push(self.active_group); // 1 byte
        buf.push(self.skip_remaining_slots); // 1 byte
        buf.extend_from_slice(&self.switch_timer_val.to_be_bytes()); // 2 bytes
        buf.extend_from_slice(&self.total_candidates.to_be_bytes()); // 2 bytes
        buf.extend_from_slice(&self.max_candidates.to_be_bytes()); // 2 bytes

        let crc = compute_crc16(&buf);
        buf.extend_from_slice(&crc.to_be_bytes()); // 2 bytes (total 18 bytes)
        buf
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, PdcchPowerSavingError> {
        if bytes.len() < 18 {
            return Err(PdcchPowerSavingError::WirePayloadTooShort {
                needed: 18,
                found: bytes.len(),
            });
        }

        let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != SSGS_WIRE_MAGIC {
            return Err(PdcchPowerSavingError::InvalidWireMagic(magic));
        }

        let body_len = bytes.len() - 2;
        let expected_crc = u16::from_be_bytes([bytes[body_len], bytes[body_len + 1]]);
        let computed_crc = compute_crc16(&bytes[..body_len]);
        if expected_crc != computed_crc {
            return Err(PdcchPowerSavingError::WireCrcMismatch {
                expected: expected_crc,
                computed: computed_crc,
            });
        }

        let sfn = u16::from_be_bytes([bytes[4], bytes[5]]);
        let slot = u16::from_be_bytes([bytes[6], bytes[7]]);
        let active_group = bytes[8];
        let skip_remaining_slots = bytes[9];
        let switch_timer_val = u16::from_be_bytes([bytes[10], bytes[11]]);
        let total_candidates = u16::from_be_bytes([bytes[12], bytes[13]]);
        let max_candidates = u16::from_be_bytes([bytes[14], bytes[15]]);

        Ok(Self {
            sfn,
            slot,
            active_group,
            skip_remaining_slots,
            switch_timer_val,
            total_candidates,
            max_candidates,
        })
    }
}

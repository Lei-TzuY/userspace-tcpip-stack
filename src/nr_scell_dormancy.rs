//! 3GPP Release 18 / Release 19 Fast SCell Activation, Dormancy & Multi-Carrier Power Saving Engine.
//!
//! Conforms to:
//! - 3GPP TS 38.321 Rel-18 §5.9: SCell activation/deactivation and dormancy handling.
//! - 3GPP TS 38.321 Rel-18 §6.1.3.10 & §6.1.3.35: SCell Activation/Deactivation MAC CEs
//!   (LCID 61, 62) and SCell Dormancy/Activation/Deactivation MAC CEs (LCID 51, 52).
//! - 3GPP TS 38.213 Rel-18 §11.1: UE procedure for receiving control information - SCell dormancy
//!   indication via DCI formats 0_1, 1_1, and 2_6 (Dormancy Indicator field).
//! - 3GPP TS 38.331 Rel-18: Radio Resource Control - `sCellState`, `dormantBWP-Id`,
//!   `sCellDeactivationTimer`, `sCellDormancyTimer`, SCell groups.
//! - 3GPP TR 38.840 Rel-18: Study on NR Coverage & Energy Reduction Enhancements.
//!
//! Key Architecture:
//! 1. Tri-State SCell Finite State Machine (FSM):
//!    - `Activated`: Full PDCCH monitoring, CSI reporting, SRS transmissions, PUSCH/PDSCH data.
//!    - `Dormant`: Stopped PDCCH monitoring & data scheduling, BUT continuous CSI-RS/SSB beam
//!      tracking and CQI/PMI/RI reporting on PCell/PUCCH-SCell via `dormantBWP-Id`. Enables
//!      ultra-fast (2-4 ms) ramp-up without RRC reconfiguration delays.
//!    - `Deactivated`: Stopped PDCCH monitoring, CSI reporting, SRS, and RF paths (95%+ power cut).
//! 2. Fast L1 DCI SCell State Switching:
//!    - DCI Format 0_1 / 1_1 / 2_6 bitmap parsing with per-SCell or per-SCell-group mapping.
//!    - Reduces SCell activation latency from ~24-34 ms (MAC CE + RRC) down to ~2-4 ms (L1 DCI).
//! 3. MAC Control Element Binary Codec:
//!    - 1-octet (LCID 62) & 4-octet (LCID 61) SCell Activation/Deactivation MAC CEs.
//!    - 1-octet (LCID 52) & 4-octet (LCID 51) SCell Dormancy/Activation/Deactivation MAC CEs
//!      with 2-bit state encoding (00: Deactivated, 01: Dormant, 10: Activated, 11: Reserved).
//! 4. Dual Timer Management Engine:
//!    - `sCellDeactivationTimer`: Controls fallback from Activated or Dormant to Deactivated.
//!    - `sCellDormancyTimer`: Controls automatic fallback from Activated to Dormant upon data inactivity.
//! 5. Synchronized SCell Group Control:
//!    - Gangs multiple secondary carriers (e.g., mmWave FR2 band or FR1 mid-band) into synchronized
//!      dormancy groups for coordinated single-DCI wake-up/sleep.
//! 6. Energy Consumption & Battery Longevity Analytical Model:
//!    - Models real-world RF/baseband power draws across Active (800 mW), Dormant (150 mW), and
//!      Deactivated (10 mW) states.
//!    - Computes cumulative energy saved (Joules), effective duty cycle, and extended battery runtime.
//!
//! Pure standard Rust with zero external dependencies.

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Constants & LCID Definitions (TS 38.321 Rel-18 Table 6.2.1-1 / 6.2.1-2)
// ---------------------------------------------------------------------------

/// Maximum serving cells supported in 5G NR Carrier Aggregation (TS 38.331).
pub const MAX_SCELLS: usize = 31;

/// Maximum SCell groups per UE (TS 38.331).
pub const MAX_SCELL_GROUPS: usize = 4;

/// MAC LCID for 1-octet SCell Activation/Deactivation MAC CE (TS 38.321 §6.2.1).
pub const LCID_SCELL_ACT_DEACT_1_OCTET: u8 = 62;

/// MAC LCID for 4-octet SCell Activation/Deactivation MAC CE (TS 38.321 §6.2.1).
pub const LCID_SCELL_ACT_DEACT_4_OCTET: u8 = 61;

/// MAC LCID for 1-octet SCell Dormancy/Activation/Deactivation MAC CE (TS 38.321 §6.2.1).
pub const LCID_SCELL_DORMANCY_1_OCTET: u8 = 52;

/// MAC LCID for 4-octet SCell Dormancy/Activation/Deactivation MAC CE (TS 38.321 §6.2.1).
pub const LCID_SCELL_DORMANCY_4_OCTET: u8 = 51;

/// Typical L1 DCI activation latency in milliseconds (TS 38.213).
pub const L1_DCI_ACTIVATION_LATENCY_MS: u32 = 4;

/// Typical MAC CE activation latency from dormant state in milliseconds.
pub const MAC_CE_DORMANT_ACTIVATION_LATENCY_MS: u32 = 6;

/// Typical cold activation latency from deactivated state in milliseconds (RF warmup + sync).
pub const COLD_ACTIVATION_LATENCY_MS: u32 = 24;

/// Default power draw in Activated state (milliwatts).
pub const DEFAULT_POWER_ACTIVATED_MW: f64 = 850.0;

/// Default power draw in Dormant state (milliwatts) - saves ~80% power while maintaining CSI.
pub const DEFAULT_POWER_DORMANT_MW: f64 = 160.0;

/// Default power draw in Deactivated state (milliwatts) - RF front-end powered off.
pub const DEFAULT_POWER_DEACTIVATED_MW: f64 = 15.0;

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

/// Errors encountered in Fast SCell Dormancy & Activation operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SCellError {
    InvalidSCellId(u8),
    InvalidGroupId(u8),
    SCellAlreadyExists(u8),
    SCellNotFound(u8),
    InvalidBwpConfiguration(String),
    MacCeBufferTooShort { expected: usize, actual: usize },
    InvalidMacCePayload(String),
    InvalidLcid(u8),
    TimerError(String),
}

impl fmt::Display for SCellError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SCellError::InvalidSCellId(id) => write!(f, "Invalid SCell ID: {} (valid: 1..=31)", id),
            SCellError::InvalidGroupId(g) => write!(f, "Invalid SCell Group ID: {} (valid: 0..=3)", g),
            SCellError::SCellAlreadyExists(id) => write!(f, "SCell with ID {} already registered", id),
            SCellError::SCellNotFound(id) => write!(f, "SCell with ID {} not found", id),
            SCellError::InvalidBwpConfiguration(msg) => write!(f, "Invalid BWP configuration: {}", msg),
            SCellError::MacCeBufferTooShort { expected, actual } => {
                write!(f, "MAC CE buffer too short: expected {} bytes, got {}", expected, actual)
            }
            SCellError::InvalidMacCePayload(msg) => write!(f, "Invalid MAC CE payload: {}", msg),
            SCellError::InvalidLcid(lcid) => write!(f, "Unsupported MAC CE LCID: {}", lcid),
            SCellError::TimerError(msg) => write!(f, "SCell timer error: {}", msg),
        }
    }
}

// ---------------------------------------------------------------------------
// Enumerations
// ---------------------------------------------------------------------------

/// Tri-state operational mode of a Secondary Cell (TS 38.321 §5.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SCellState {
    /// Deactivated state: No PDCCH monitoring, no CSI reporting, RF off.
    Deactivated,
    /// Dormant state: No PDCCH monitoring, but active CSI reporting & beam tracking on dormant BWP.
    Dormant,
    /// Activated state: Normal data scheduling, PDCCH monitoring, PUSCH/PDSCH enabled.
    Activated,
}

impl fmt::Display for SCellState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SCellState::Deactivated => write!(f, "Deactivated"),
            SCellState::Dormant => write!(f, "Dormant"),
            SCellState::Activated => write!(f, "Activated"),
        }
    }
}

/// 2-bit state field in SCell Dormancy/Activation/Deactivation MAC CE (TS 38.321 §6.1.3.35).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TwoBitState {
    Deactivated = 0b00,
    Dormant = 0b01,
    Activated = 0b10,
    Reserved = 0b11,
}

impl TwoBitState {
    pub fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0b00 => TwoBitState::Deactivated,
            0b01 => TwoBitState::Dormant,
            0b10 => TwoBitState::Activated,
            _ => TwoBitState::Reserved,
        }
    }

    pub fn to_scell_state(&self) -> Option<SCellState> {
        match self {
            TwoBitState::Deactivated => Some(SCellState::Deactivated),
            TwoBitState::Dormant => Some(SCellState::Dormant),
            TwoBitState::Activated => Some(SCellState::Activated),
            TwoBitState::Reserved => None,
        }
    }

    pub fn from_scell_state(state: SCellState) -> Self {
        match state {
            SCellState::Deactivated => TwoBitState::Deactivated,
            SCellState::Dormant => TwoBitState::Dormant,
            SCellState::Activated => TwoBitState::Activated,
        }
    }
}

/// Downlink Control Information (DCI) formats carrying dormancy indications.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DciDormancyFormat {
    /// DCI Format 0_1: Uplink grant with 1..5 bit Dormancy Indicator.
    Dci0_1,
    /// DCI Format 1_1: Downlink assignment with 1..5 bit Dormancy Indicator.
    Dci1_1,
    /// DCI Format 2_6: Power saving DCI with Dormancy Indication bitmap.
    Dci2_6,
}

/// Cause triggering an SCell state transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionCause {
    L1DciIndication(DciDormancyFormat),
    MacCeCommand { lcid: u8 },
    DeactivationTimerExpiry,
    DormancyTimerExpiry,
    RrcReconfiguration,
    TrafficDemandRampUp,
}

impl fmt::Display for TransitionCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransitionCause::L1DciIndication(fmt) => write!(f, "L1 DCI ({:?})", fmt),
            TransitionCause::MacCeCommand { lcid } => write!(f, "MAC CE (LCID {})", lcid),
            TransitionCause::DeactivationTimerExpiry => write!(f, "sCellDeactivationTimer expiry"),
            TransitionCause::DormancyTimerExpiry => write!(f, "sCellDormancyTimer expiry"),
            TransitionCause::RrcReconfiguration => write!(f, "RRC Reconfiguration"),
            TransitionCause::TrafficDemandRampUp => write!(f, "Traffic Demand Ramp-Up"),
        }
    }
}

/// SCell state transition event record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SCellStateTransition {
    pub scell_id: u8,
    pub previous_state: SCellState,
    pub new_state: SCellState,
    pub active_bwp_id: u8,
    pub cause: TransitionCause,
    pub timestamp_ms: u64,
}

// ---------------------------------------------------------------------------
// Configuration & Telemetry Structures
// ---------------------------------------------------------------------------

/// Configuration for a Secondary Cell (SCell) per TS 38.331.
#[derive(Debug, Clone, PartialEq)]
pub struct SCellConfig {
    /// SCell Index (1..31).
    pub scell_id: u8,
    /// Optional SCell Group ID (0..3) for synchronized group dormancy control.
    pub group_id: Option<u8>,
    /// Active DL BWP ID when in Activated state.
    pub active_bwp_id: u8,
    /// Dormant BWP ID when in Dormant state (must be configured for dormancy support).
    pub dormant_bwp_id: Option<u8>,
    /// First active BWP ID after activation from deactivated state.
    pub first_active_bwp_id: u8,
    /// Duration of `sCellDeactivationTimer` in ms (0 = infinity).
    pub deactivation_timer_ms: u32,
    /// Optional duration of `sCellDormancyTimer` in ms (None = timer disabled).
    pub dormancy_timer_ms: Option<u32>,
    /// RF power consumption in Activated state (mW).
    pub power_activated_mw: f64,
    /// RF power consumption in Dormant state (mW).
    pub power_dormant_mw: f64,
    /// RF power consumption in Deactivated state (mW).
    pub power_deactivated_mw: f64,
}

impl SCellConfig {
    pub fn new(scell_id: u8, active_bwp_id: u8, dormant_bwp_id: Option<u8>) -> Result<Self, SCellError> {
        if scell_id == 0 || scell_id > MAX_SCELLS as u8 {
            return Err(SCellError::InvalidSCellId(scell_id));
        }
        Ok(Self {
            scell_id,
            group_id: None,
            active_bwp_id,
            dormant_bwp_id,
            first_active_bwp_id: active_bwp_id,
            deactivation_timer_ms: 160, // Default 160 ms per TS 38.331
            dormancy_timer_ms: None,
            power_activated_mw: DEFAULT_POWER_ACTIVATED_MW,
            power_dormant_mw: DEFAULT_POWER_DORMANT_MW,
            power_deactivated_mw: DEFAULT_POWER_DEACTIVATED_MW,
        })
    }

    pub fn with_group(mut self, group_id: u8) -> Result<Self, SCellError> {
        if group_id >= MAX_SCELL_GROUPS as u8 {
            return Err(SCellError::InvalidGroupId(group_id));
        }
        self.group_id = Some(group_id);
        Ok(self)
    }

    pub fn with_timers(mut self, deact_ms: u32, dorm_ms: Option<u32>) -> Self {
        self.deactivation_timer_ms = deact_ms;
        self.dormancy_timer_ms = dorm_ms;
        self
    }

    pub fn with_power_profile(mut self, activated_mw: f64, dormant_mw: f64, deactivated_mw: f64) -> Self {
        self.power_activated_mw = activated_mw;
        self.power_dormant_mw = dormant_mw;
        self.power_deactivated_mw = deactivated_mw;
        self
    }
}

/// Dynamic runtime state of an SCell.
#[derive(Debug, Clone, PartialEq)]
pub struct SCellRuntimeState {
    pub scell_id: u8,
    pub current_state: SCellState,
    pub current_bwp_id: u8,
    pub time_in_state_ms: u64,
    pub deactivation_timer_remaining_ms: Option<u32>,
    pub dormancy_timer_remaining_ms: Option<u32>,
    pub last_reported_cqi: Option<u8>,
    pub last_rsrp_dbm: Option<f32>,
    pub cumulative_energy_consumed_mj: f64,
}

impl SCellRuntimeState {
    pub fn new(scell_id: u8, initial_bwp: u8) -> Self {
        Self {
            scell_id,
            current_state: SCellState::Deactivated,
            current_bwp_id: initial_bwp,
            time_in_state_ms: 0,
            deactivation_timer_remaining_ms: None,
            dormancy_timer_remaining_ms: None,
            last_reported_cqi: None,
            last_rsrp_dbm: None,
            cumulative_energy_consumed_mj: 0.0,
        }
    }
}

/// Comprehensive telemetry and performance metrics for the SCell dormancy subsystem.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SCellTelemetry {
    pub l1_fast_activations: u64,
    pub l1_dormancy_switches: u64,
    pub mac_ce_activations: u64,
    pub mac_ce_dormancy_switches: u64,
    pub mac_ce_deactivations: u64,
    pub deactivation_timer_expiries: u64,
    pub dormancy_timer_expiries: u64,
    pub total_cqi_reports_in_dormancy: u64,
    pub total_energy_consumed_joules: f64,
    pub baseline_energy_without_dormancy_joules: f64,
    pub total_active_time_ms: u64,
    pub total_dormant_time_ms: u64,
    pub total_deactivated_time_ms: u64,
}

impl SCellTelemetry {
    /// Computes percentage energy saved compared to keeping SCells continuously active.
    pub fn energy_savings_percentage(&self) -> f64 {
        if self.baseline_energy_without_dormancy_joules <= 0.0 {
            return 0.0;
        }
        let diff = self.baseline_energy_without_dormancy_joules - self.total_energy_consumed_joules;
        if diff <= 0.0 {
            0.0
        } else {
            (diff / self.baseline_energy_without_dormancy_joules) * 100.0
        }
    }

    /// Computes the ratio of time spent in power-saving states (Dormant + Deactivated).
    pub fn power_save_duty_cycle(&self) -> f64 {
        let total = self.total_active_time_ms + self.total_dormant_time_ms + self.total_deactivated_time_ms;
        if total == 0 {
            0.0
        } else {
            (self.total_dormant_time_ms + self.total_deactivated_time_ms) as f64 / total as f64
        }
    }
}

// ---------------------------------------------------------------------------
// Fast SCell Activation & Dormancy Engine
// ---------------------------------------------------------------------------

/// Central engine managing 3GPP Rel-18/19 Fast SCell Activation, Dormancy, and MAC/PHY coordination.
pub struct FastSCellDormancyEngine {
    configs: HashMap<u8, SCellConfig>,
    states: HashMap<u8, SCellRuntimeState>,
    current_time_ms: u64,
    telemetry: SCellTelemetry,
}

impl FastSCellDormancyEngine {
    /// Creates a new, empty SCell dormancy engine.
    pub fn new() -> Self {
        Self {
            configs: HashMap::new(),
            states: HashMap::new(),
            current_time_ms: 0,
            telemetry: SCellTelemetry::default(),
        }
    }

    /// Registers a new Secondary Cell with its configuration.
    pub fn add_scell(&mut self, config: SCellConfig) -> Result<(), SCellError> {
        let id = config.scell_id;
        if id == 0 || id > MAX_SCELLS as u8 {
            return Err(SCellError::InvalidSCellId(id));
        }
        if self.configs.contains_key(&id) {
            return Err(SCellError::SCellAlreadyExists(id));
        }
        let initial_bwp = config.first_active_bwp_id;
        self.states.insert(id, SCellRuntimeState::new(id, initial_bwp));
        self.configs.insert(id, config);
        Ok(())
    }

    /// Returns a reference to the configuration of a specific SCell.
    pub fn get_config(&self, scell_id: u8) -> Option<&SCellConfig> {
        self.configs.get(&scell_id)
    }

    /// Returns a reference to the dynamic state of a specific SCell.
    pub fn get_state(&self, scell_id: u8) -> Option<&SCellRuntimeState> {
        self.states.get(&scell_id)
    }

    /// Returns the number of registered SCells.
    pub fn scell_count(&self) -> usize {
        self.configs.len()
    }

    /// Returns a reference to the telemetry tracker.
    pub fn telemetry(&self) -> &SCellTelemetry {
        &self.telemetry
    }

    /// Current simulated clock in milliseconds.
    pub fn current_time_ms(&self) -> u64 {
        self.current_time_ms
    }

    // -----------------------------------------------------------------------
    // State Switching Operations
    // -----------------------------------------------------------------------

    /// Internal state transition logic enforcing BWP switching, timer reset, and telemetry updates.
    fn perform_state_transition(
        &mut self,
        scell_id: u8,
        target_state: SCellState,
        cause: TransitionCause,
    ) -> Result<Option<SCellStateTransition>, SCellError> {
        let config = self.configs.get(&scell_id).ok_or(SCellError::SCellNotFound(scell_id))?.clone();
        let state = self.states.get_mut(&scell_id).ok_or(SCellError::SCellNotFound(scell_id))?;

        if state.current_state == target_state {
            // State is unchanged; however, receiving an activation command for an already active cell
            // restarts the deactivation timer per TS 38.321 §5.9.
            if target_state == SCellState::Activated && config.deactivation_timer_ms > 0 {
                state.deactivation_timer_remaining_ms = Some(config.deactivation_timer_ms);
            }
            return Ok(None);
        }

        // Validate dormant BWP presence if entering Dormant state
        if target_state == SCellState::Dormant && config.dormant_bwp_id.is_none() {
            return Err(SCellError::InvalidBwpConfiguration(format!(
                "SCell {} does not have a dormantBWP-Id configured",
                scell_id
            )));
        }

        let prev_state = state.current_state;
        state.current_state = target_state;
        state.time_in_state_ms = 0;

        // BWP Switching and Timer management per target state
        match target_state {
            SCellState::Activated => {
                state.current_bwp_id = config.active_bwp_id;
                // Start or restart sCellDeactivationTimer
                if config.deactivation_timer_ms > 0 {
                    state.deactivation_timer_remaining_ms = Some(config.deactivation_timer_ms);
                } else {
                    state.deactivation_timer_remaining_ms = None;
                }
                // Start sCellDormancyTimer if configured
                state.dormancy_timer_remaining_ms = config.dormancy_timer_ms;
            }
            SCellState::Dormant => {
                state.current_bwp_id = config.dormant_bwp_id.unwrap();
                // When entering dormant state, sCellDeactivationTimer continues running or restarts
                if config.deactivation_timer_ms > 0 {
                    state.deactivation_timer_remaining_ms = Some(config.deactivation_timer_ms);
                }
                state.dormancy_timer_remaining_ms = None;
            }
            SCellState::Deactivated => {
                state.current_bwp_id = config.first_active_bwp_id;
                state.deactivation_timer_remaining_ms = None;
                state.dormancy_timer_remaining_ms = None;
            }
        }

        // Record telemetry events
        match &cause {
            TransitionCause::L1DciIndication(_) => match target_state {
                SCellState::Activated => self.telemetry.l1_fast_activations += 1,
                SCellState::Dormant => self.telemetry.l1_dormancy_switches += 1,
                _ => {}
            },
            TransitionCause::MacCeCommand { .. } => match target_state {
                SCellState::Activated => self.telemetry.mac_ce_activations += 1,
                SCellState::Dormant => self.telemetry.mac_ce_dormancy_switches += 1,
                SCellState::Deactivated => self.telemetry.mac_ce_deactivations += 1,
            },
            TransitionCause::DeactivationTimerExpiry => self.telemetry.deactivation_timer_expiries += 1,
            TransitionCause::DormancyTimerExpiry => self.telemetry.dormancy_timer_expiries += 1,
            _ => {}
        }

        let transition = SCellStateTransition {
            scell_id,
            previous_state: prev_state,
            new_state: target_state,
            active_bwp_id: state.current_bwp_id,
            cause,
            timestamp_ms: self.current_time_ms,
        };

        Ok(Some(transition))
    }

    // -----------------------------------------------------------------------
    // Fast L1 DCI Control (TS 38.213 §11.1)
    // -----------------------------------------------------------------------

    /// Processes an L1 DCI Dormancy Indication bitmap (DCI 0_1, 1_1, or 2_6).
    ///
    /// The `dormancy_bitmap` provides 1 bit per SCell or SCell group:
    /// - Bit 0 (or '0'): Switch to Dormant BWP (Dormant state)
    /// - Bit 1 (or '1'): Switch to Non-Dormant BWP (Activated state)
    ///
    /// If `scell_or_group_ids` is provided, the bits in `dormancy_bitmap` correspond to the
    /// indices in that slice (bit 0 -> slice[0], bit 1 -> slice[1], etc.).
    /// Otherwise, bit (k-1) directly maps to SCell ID k (1..=31).
    pub fn process_l1_dci_dormancy(
        &mut self,
        format: DciDormancyFormat,
        dormancy_bitmap: u32,
        scell_or_group_ids: Option<&[u8]>,
        is_group_addressing: bool,
    ) -> Result<Vec<SCellStateTransition>, SCellError> {
        let mut transitions = Vec::new();
        let cause = TransitionCause::L1DciIndication(format);

        if is_group_addressing {
            // Bits correspond to SCell Group IDs
            let groups = match scell_or_group_ids {
                Some(g) => g.to_vec(),
                None => (0..MAX_SCELL_GROUPS as u8).collect(),
            };

            for (bit_idx, &group_id) in groups.iter().enumerate() {
                if bit_idx >= 32 {
                    break;
                }
                let bit_val = (dormancy_bitmap >> bit_idx) & 0x01;
                let target_state = if bit_val == 1 {
                    SCellState::Activated
                } else {
                    SCellState::Dormant
                };

                // Find all SCells belonging to this group
                let matched_scell_ids: Vec<u8> = self
                    .configs
                    .iter()
                    .filter(|(_, cfg)| cfg.group_id == Some(group_id))
                    .map(|(&id, _)| id)
                    .collect();

                for scell_id in matched_scell_ids {
                    // Only transition cells that are not Deactivated (L1 DCI cannot awaken Deactivated cells per Rel-18)
                    if let Some(curr) = self.states.get(&scell_id) {
                        if curr.current_state != SCellState::Deactivated {
                            if let Some(t) = self.perform_state_transition(scell_id, target_state, cause.clone())? {
                                transitions.push(t);
                            }
                        }
                    }
                }
            }
        } else {
            // Direct SCell bitmapping
            let ids: Vec<u8> = match scell_or_group_ids {
                Some(slice) => slice.to_vec(),
                None => {
                    let mut all_ids: Vec<u8> = self.configs.keys().copied().collect();
                    all_ids.sort_unstable();
                    all_ids
                }
            };

            for (bit_idx, &scell_id) in ids.iter().enumerate() {
                if bit_idx >= 32 {
                    break;
                }
                let bit_val = (dormancy_bitmap >> bit_idx) & 0x01;
                let target_state = if bit_val == 1 {
                    SCellState::Activated
                } else {
                    SCellState::Dormant
                };

                if let Some(curr) = self.states.get(&scell_id) {
                    // L1 DCI switches between Dormant and Activated
                    if curr.current_state != SCellState::Deactivated {
                        if let Some(t) = self.perform_state_transition(scell_id, target_state, cause.clone())? {
                            transitions.push(t);
                        }
                    }
                }
            }
        }

        Ok(transitions)
    }

    // -----------------------------------------------------------------------
    // MAC Control Element Codec (TS 38.321 §6.1.3.10 & §6.1.3.35)
    // -----------------------------------------------------------------------

    /// Decodes and applies an SCell MAC Control Element payload.
    ///
    /// Supported LCIDs:
    /// - 62: 1-octet SCell Activation/Deactivation (SCells 1..7)
    /// - 61: 4-octet SCell Activation/Deactivation (SCells 1..31)
    /// - 52: 1-octet SCell Dormancy/Activation/Deactivation (SCells 1..4, 2 bits each)
    /// - 51: 4-octet SCell Dormancy/Activation/Deactivation (SCells 1..15 or 1..16, 2 bits each)
    pub fn decode_and_apply_mac_ce(
        &mut self,
        lcid: u8,
        payload: &[u8],
    ) -> Result<Vec<SCellStateTransition>, SCellError> {
        let mut transitions = Vec::new();
        let cause = TransitionCause::MacCeCommand { lcid };

        match lcid {
            LCID_SCELL_ACT_DEACT_1_OCTET => {
                if payload.is_empty() {
                    return Err(SCellError::MacCeBufferTooShort { expected: 1, actual: payload.len() });
                }
                let byte = payload[0];
                // Bits C7..C1 correspond to SCell ID 7..1. Bit 0 (R) is reserved.
                for scell_id in 1..=7 {
                    let bit = (byte >> scell_id) & 0x01;
                    let target_state = if bit == 1 {
                        SCellState::Activated
                    } else {
                        SCellState::Deactivated
                    };
                    if self.configs.contains_key(&scell_id) {
                        if let Some(t) = self.perform_state_transition(scell_id, target_state, cause.clone())? {
                            transitions.push(t);
                        }
                    }
                }
            }

            LCID_SCELL_ACT_DEACT_4_OCTET => {
                if payload.len() < 4 {
                    return Err(SCellError::MacCeBufferTooShort { expected: 4, actual: payload.len() });
                }
                // 32-bit field: C31..C1, followed by R (or standard big-endian octet layout)
                // In TS 38.321 §6.1.3.10:
                // Octet 1: C7..C1, R
                // Octet 2: C15..C8
                // Octet 3: C23..C16
                // Octet 4: C31..C24
                for scell_id in 1..=31 {
                    let byte_idx = if scell_id <= 7 {
                        0
                    } else {
                        1 + ((scell_id - 8) / 8) as usize
                    };
                    let bit_offset = if scell_id <= 7 {
                        scell_id
                    } else {
                        (scell_id - 8) % 8
                    };
                    let bit = (payload[byte_idx] >> bit_offset) & 0x01;
                    let target_state = if bit == 1 {
                        SCellState::Activated
                    } else {
                        SCellState::Deactivated
                    };
                    if self.configs.contains_key(&scell_id) {
                        if let Some(t) = self.perform_state_transition(scell_id, target_state, cause.clone())? {
                            transitions.push(t);
                        }
                    }
                }
            }

            LCID_SCELL_DORMANCY_1_OCTET => {
                if payload.is_empty() {
                    return Err(SCellError::MacCeBufferTooShort { expected: 1, actual: payload.len() });
                }
                let byte = payload[0];
                // In TS 38.321 §6.1.3.35, 1-octet format:
                // C4 (bits 7-6), C3 (bits 5-4), C2 (bits 3-2), C1 (bits 1-0)
                for scell_id in 1..=4 {
                    let shift = (scell_id - 1) * 2;
                    let bits = (byte >> shift) & 0b11;
                    if let Some(target_state) = TwoBitState::from_bits(bits).to_scell_state() {
                        if self.configs.contains_key(&scell_id) {
                            if let Some(t) = self.perform_state_transition(scell_id, target_state, cause.clone())? {
                                transitions.push(t);
                            }
                        }
                    }
                }
            }

            LCID_SCELL_DORMANCY_4_OCTET => {
                if payload.len() < 4 {
                    return Err(SCellError::MacCeBufferTooShort { expected: 4, actual: payload.len() });
                }
                // 4-octet format: 32 bits = 16 SCells (SCells 1..16), 2 bits each
                for scell_id in 1..=16 {
                    let cell_idx = (scell_id - 1) as usize;
                    let byte_idx = cell_idx / 4;
                    let shift = (cell_idx % 4) * 2;
                    let bits = (payload[byte_idx] >> shift) & 0b11;
                    if let Some(target_state) = TwoBitState::from_bits(bits).to_scell_state() {
                        if self.configs.contains_key(&scell_id) {
                            if let Some(t) = self.perform_state_transition(scell_id, target_state, cause.clone())? {
                                transitions.push(t);
                            }
                        }
                    }
                }
            }

            _ => return Err(SCellError::InvalidLcid(lcid)),
        }

        Ok(transitions)
    }

    /// Encodes an SCell MAC Control Element binary payload from requested target states.
    pub fn encode_mac_ce(
        &self,
        lcid: u8,
        target_states: &HashMap<u8, SCellState>,
    ) -> Result<Vec<u8>, SCellError> {
        match lcid {
            LCID_SCELL_ACT_DEACT_1_OCTET => {
                let mut byte = 0u8;
                for (&id, &state) in target_states {
                    if id >= 1 && id <= 7 && state == SCellState::Activated {
                        byte |= 1 << id;
                    }
                }
                Ok(vec![byte])
            }

            LCID_SCELL_ACT_DEACT_4_OCTET => {
                let mut bytes = vec![0u8; 4];
                for (&id, &state) in target_states {
                    if id >= 1 && id <= 31 && state == SCellState::Activated {
                        if id <= 7 {
                            bytes[0] |= 1 << id;
                        } else {
                            let byte_idx = 1 + ((id - 8) / 8) as usize;
                            let bit_offset = (id - 8) % 8;
                            bytes[byte_idx] |= 1 << bit_offset;
                        }
                    }
                }
                Ok(bytes)
            }

            LCID_SCELL_DORMANCY_1_OCTET => {
                let mut byte = 0u8;
                for (&id, &state) in target_states {
                    if id >= 1 && id <= 4 {
                        let two_bit = TwoBitState::from_scell_state(state) as u8;
                        let shift = (id - 1) * 2;
                        byte |= two_bit << shift;
                    }
                }
                Ok(vec![byte])
            }

            LCID_SCELL_DORMANCY_4_OCTET => {
                let mut bytes = vec![0u8; 4];
                for (&id, &state) in target_states {
                    if id >= 1 && id <= 16 {
                        let cell_idx = (id - 1) as usize;
                        let byte_idx = cell_idx / 4;
                        let shift = (cell_idx % 4) * 2;
                        let two_bit = TwoBitState::from_scell_state(state) as u8;
                        bytes[byte_idx] |= two_bit << shift;
                    }
                }
                Ok(bytes)
            }

            _ => Err(SCellError::InvalidLcid(lcid)),
        }
    }

    // -----------------------------------------------------------------------
    // Temporal Advancement & Timer Management
    // -----------------------------------------------------------------------

    /// Advances simulation time by `delta_ms`, updating timers, state transitions, and power draw.
    pub fn advance_time_ms(&mut self, delta_ms: u32) -> Vec<SCellStateTransition> {
        let mut transitions = Vec::new();
        self.current_time_ms += delta_ms as u64;

        // Collect all IDs to avoid borrow conflicts
        let ids: Vec<u8> = self.configs.keys().copied().collect();

        for id in ids {
            let config = self.configs.get(&id).unwrap().clone();
            let state = self.states.get_mut(&id).unwrap();

            state.time_in_state_ms += delta_ms as u64;

            // Update energy consumption for this SCell
            let power_mw = match state.current_state {
                SCellState::Activated => config.power_activated_mw,
                SCellState::Dormant => config.power_dormant_mw,
                SCellState::Deactivated => config.power_deactivated_mw,
            };
            let energy_mj = power_mw * (delta_ms as f64);
            state.cumulative_energy_consumed_mj += energy_mj;

            // Global telemetry updates
            let energy_j = energy_mj / 1_000.0;
            self.telemetry.total_energy_consumed_joules += energy_j;
            self.telemetry.baseline_energy_without_dormancy_joules += (config.power_activated_mw * delta_ms as f64) / 1_000.0;

            match state.current_state {
                SCellState::Activated => self.telemetry.total_active_time_ms += delta_ms as u64,
                SCellState::Dormant => self.telemetry.total_dormant_time_ms += delta_ms as u64,
                SCellState::Deactivated => self.telemetry.total_deactivated_time_ms += delta_ms as u64,
            }

            // 1. Check sCellDeactivationTimer
            let mut deact_expired = false;
            if let Some(remaining) = state.deactivation_timer_remaining_ms {
                if remaining <= delta_ms {
                    state.deactivation_timer_remaining_ms = None;
                    deact_expired = true;
                } else {
                    state.deactivation_timer_remaining_ms = Some(remaining - delta_ms);
                }
            }

            // 2. Check sCellDormancyTimer
            let mut dorm_expired = false;
            if let Some(remaining) = state.dormancy_timer_remaining_ms {
                if remaining <= delta_ms {
                    state.dormancy_timer_remaining_ms = None;
                    dorm_expired = true;
                } else {
                    state.dormancy_timer_remaining_ms = Some(remaining - delta_ms);
                }
            }

            // Prioritize deactivation over dormancy if both trigger simultaneously
            if deact_expired && state.current_state != SCellState::Deactivated {
                if let Ok(Some(t)) = self.perform_state_transition(
                    id,
                    SCellState::Deactivated,
                    TransitionCause::DeactivationTimerExpiry,
                ) {
                    transitions.push(t);
                }
            } else if dorm_expired && state.current_state == SCellState::Activated {
                if let Ok(Some(t)) = self.perform_state_transition(
                    id,
                    SCellState::Dormant,
                    TransitionCause::DormancyTimerExpiry,
                ) {
                    transitions.push(t);
                }
            }
        }

        transitions
    }

    // -----------------------------------------------------------------------
    // Channel Quality Information (CQI) Tracking on Dormant BWP
    // -----------------------------------------------------------------------

    /// Records a CQI and RSRP measurement on the SCell (even while in Dormant state).
    pub fn record_cqi(&mut self, scell_id: u8, cqi: u8, rsrp_dbm: f32) -> Result<(), SCellError> {
        let state = self.states.get_mut(&scell_id).ok_or(SCellError::SCellNotFound(scell_id))?;
        state.last_reported_cqi = Some(cqi);
        state.last_rsrp_dbm = Some(rsrp_dbm);

        if state.current_state == SCellState::Dormant {
            self.telemetry.total_cqi_reports_in_dormancy += 1;
        }
        Ok(())
    }

    /// Predicts activation latency in milliseconds based on current state.
    ///
    /// - If already Activated: 0 ms.
    /// - If Dormant: 2-4 ms (fast L1 DCI activation with fresh channel state).
    /// - If Deactivated: 24-34 ms (cold start RF PLL lock + RRC sync).
    pub fn predict_activation_latency_ms(&self, scell_id: u8) -> Result<u32, SCellError> {
        let state = self.states.get(&scell_id).ok_or(SCellError::SCellNotFound(scell_id))?;
        match state.current_state {
            SCellState::Activated => Ok(0),
            SCellState::Dormant => Ok(L1_DCI_ACTIVATION_LATENCY_MS),
            SCellState::Deactivated => Ok(COLD_ACTIVATION_LATENCY_MS),
        }
    }

    /// Computes instantaneous total power draw across all registered SCells in milliwatts.
    pub fn current_power_draw_mw(&self) -> f64 {
        let mut total = 0.0;
        for (id, state) in &self.states {
            if let Some(config) = self.configs.get(id) {
                total += match state.current_state {
                    SCellState::Activated => config.power_activated_mw,
                    SCellState::Dormant => config.power_dormant_mw,
                    SCellState::Deactivated => config.power_deactivated_mw,
                };
            }
        }
        total
    }

    /// Triggers traffic demand ramp-up, rapidly awakening a dormant or deactivated SCell.
    pub fn request_traffic_activation(&mut self, scell_id: u8) -> Result<Option<SCellStateTransition>, SCellError> {
        self.perform_state_transition(
            scell_id,
            SCellState::Activated,
            TransitionCause::TrafficDemandRampUp,
        )
    }
}

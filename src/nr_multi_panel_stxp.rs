//! 3GPP Rel-18 / Rel-19 5G NR Multi-Panel Simultaneous Transmission (STxP) Engine.
//!
//! Implements 3GPP TR 38.859, TS 38.214 §6.1.1, TS 38.213 §7.1 / §7.5, and TS 38.321 §6.1.3:
//! - Multi-panel antenna configuration and panel state lifecycle (Active, Standby, MpeThrottled, ThermalShutdown).
//! - Independent per-panel open-loop and closed-loop transmit power control (TPC).
//! - Cross-panel total maximum power ($P_{\text{CMAX,total}}$) priority-based scaling and power headroom arbitration.
//! - Maximum Permissible Exposure (MPE) sensing, P-MPR power backoff, and rolling Specific Absorption Rate (SAR) dose management.
//! - Inter-panel RF isolation margin and intermodulation distortion (IMD) protection.
//! - Rel-18 Multi-Panel Power Headroom Reporting (MP-PHR) MAC Control Element wire serialization and deserialization with CRC-16.
//! - Operational telemetry tracking total transmitted power, throughput gain, and MPE throttle events.
//!
//! Pure standard Rust with zero external dependencies.

use std::fmt;

// ---------------------------------------------------------------------------
// Constants & CRC-16
// ---------------------------------------------------------------------------

/// Maximum number of physical antenna panels supported per UE.
pub const MAX_STXP_PANELS: usize = 4;

/// Default UE maximum transmission power across all panels in dBm (Class 3 UE: 23 dBm = 200 mW).
pub const DEFAULT_P_CMAX_TOTAL_DBM: f64 = 23.0;

/// Default per-panel maximum transmission power in dBm (20 dBm = 100 mW).
pub const DEFAULT_P_CMAX_PANEL_DBM: f64 = 20.0;

/// Minimum transmission power per panel in dBm.
pub const MIN_PANEL_POWER_DBM: f64 = -40.0;

/// Maximum Permissible Exposure (MPE) regulatory SAR limit in W/kg (FCC / ICNIRP: 1.6 W/kg localized).
pub const REGULATORY_SAR_LIMIT_W_KG: f64 = 1.6;

/// Minimum required inter-panel RF isolation margin in dB to avoid excessive IMD.
pub const MIN_INTER_PANEL_ISOLATION_DB: f64 = 15.0;

/// Magic header identifier for MP-PHR binary wire reports (0x53545850 = "STXP").
pub const MP_PHR_WIRE_MAGIC: [u8; 4] = [0x53, 0x54, 0x58, 0x50];

/// CRC-16 CCITT polynomial (0x1021 = x^16 + x^12 + x^5 + 1).
pub const CRC16_CCITT_POLY: u16 = 0x1021;

/// Computes CRC-16 CCITT checksum over a slice of bytes.
pub fn compute_crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= (byte as u16) << 8;
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

/// Converts power in milliwatts to dBm.
#[inline]
pub fn mw_to_dbm(mw: f64) -> f64 {
    if mw <= 1e-12 {
        MIN_PANEL_POWER_DBM
    } else {
        10.0 * mw.log10()
    }
}

/// Converts power in dBm to milliwatts.
#[inline]
pub fn dbm_to_mw(dbm: f64) -> f64 {
    10.0_f64.powf(dbm / 10.0)
}

// ---------------------------------------------------------------------------
// Enumerations & Data Structures
// ---------------------------------------------------------------------------

/// Operational lifecycle state of an antenna panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PanelState {
    /// Active and available for simultaneous transmission.
    Active,
    /// In low-power standby mode, ready to be activated.
    Standby,
    /// Operating with MPE power reduction (P-MPR) due to body proximity.
    MpeThrottled,
    /// Shut down due to thermal overload or severe hardware constraint.
    ThermalShutdown,
}

impl PanelState {
    pub fn is_available_for_tx(&self) -> bool {
        matches!(self, PanelState::Active | PanelState::MpeThrottled)
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            PanelState::Active => 0,
            PanelState::Standby => 1,
            PanelState::MpeThrottled => 2,
            PanelState::ThermalShutdown => 3,
        }
    }

    pub fn from_u8(val: u8) -> Result<Self, StxpError> {
        match val {
            0 => Ok(PanelState::Active),
            1 => Ok(PanelState::Standby),
            2 => Ok(PanelState::MpeThrottled),
            3 => Ok(PanelState::ThermalShutdown),
            other => Err(StxpError::InvalidState(format!("Unknown panel state: {}", other))),
        }
    }
}

/// Physical uplink channel type per 3GPP TS 38.213 §7.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UlChannelType {
    /// Physical Random Access Channel (highest priority).
    Prach,
    /// PUCCH carrying HARQ-ACK and/or Scheduling Request (SR).
    PucchHarqAck,
    /// PUCCH carrying Channel State Information (CSI).
    PucchCsi,
    /// PUSCH multiplexed with HARQ-ACK.
    PuschHarqAck,
    /// PUSCH carrying standard user plane data without HARQ-ACK.
    PuschData,
    /// Sounding Reference Signal (lowest priority).
    Srs,
}

impl UlChannelType {
    /// Relative 3GPP priority ranking (0 = highest priority, 5 = lowest priority).
    pub fn priority_rank(&self) -> u8 {
        match self {
            UlChannelType::Prach => 0,
            UlChannelType::PucchHarqAck => 1,
            UlChannelType::PucchCsi => 2,
            UlChannelType::PuschHarqAck => 3,
            UlChannelType::PuschData => 4,
            UlChannelType::Srs => 5,
        }
    }
}

/// Supported 3GPP Rel-18 STxP multi-panel simultaneous transmission operational cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StxpTransmissionCase {
    /// Multi-TRP PUSCH: spatial layers or repetitions transmitted simultaneously across panels.
    SimultaneousPuschMtrp,
    /// Simultaneous PUSCH data on one panel and low-latency PUCCH on another.
    SimultaneousPuschPucch,
    /// Simultaneous PUSCH transmission on one panel and SRS beam sounding on another.
    SimultaneousPuschSrs,
    /// Simultaneous PUCCH transmissions across panels to different TRPs/CCs.
    SimultaneousPucchPucch,
}

/// Configuration parameters for an individual antenna panel.
#[derive(Debug, Clone, PartialEq)]
pub struct AntennaPanelConfig {
    pub panel_id: u8,
    pub num_tx_ports: u8,
    pub azimuth_deg: f64,
    pub elevation_deg: f64,
    pub p_cmax_p_dbm: f64,
    pub p_o_pusch_dbm: f64,
    pub alpha: f64,
}

impl AntennaPanelConfig {
    pub fn new(panel_id: u8, num_tx_ports: u8, azimuth_deg: f64, elevation_deg: f64) -> Self {
        Self {
            panel_id,
            num_tx_ports: num_tx_ports.max(1),
            azimuth_deg,
            elevation_deg,
            p_cmax_p_dbm: DEFAULT_P_CMAX_PANEL_DBM,
            p_o_pusch_dbm: -80.0,
            alpha: 0.8,
        }
    }
}

/// Transmission request on a specific antenna panel for an uplink slot.
#[derive(Debug, Clone, PartialEq)]
pub struct PanelTransmissionRequest {
    pub panel_id: u8,
    pub channel_type: UlChannelType,
    pub pathloss_db: f64,
    pub allocated_prbs: u16,
    pub tpc_command_db: f64,
    pub delta_tf_db: f64,
}

/// Per-panel scheduling and power allocation decision.
#[derive(Debug, Clone, PartialEq)]
pub struct PanelTransmissionDecision {
    pub panel_id: u8,
    pub channel_type: UlChannelType,
    pub requested_power_dbm: f64,
    pub scaled_power_dbm: f64,
    pub scaling_factor: f64, // 0.0 to 1.0
    pub p_mpr_db: f64,
    pub allocated: bool,
}

/// Scheduling outcome for an STxP uplink transmission epoch/slot.
#[derive(Debug, Clone, PartialEq)]
pub struct StxpSchedulingResult {
    pub slot_number: u32,
    pub tx_case: Option<StxpTransmissionCase>,
    pub total_requested_power_mw: f64,
    pub total_transmitted_power_mw: f64,
    pub p_cmax_total_mw: f64,
    pub power_scaled: bool,
    pub decisions: Vec<PanelTransmissionDecision>,
}

/// Multi-Panel Power Headroom entry for one active panel.
#[derive(Debug, Clone, PartialEq)]
pub struct MpPhrPanelEntry {
    pub panel_id: u8,
    pub ph_db: f32,
    pub p_cmax_p_dbm: f32,
    pub mpe_applied: bool,
}

/// 3GPP Rel-18 Multi-Panel Power Headroom Report (MP-PHR) MAC Control Element structure.
#[derive(Debug, Clone, PartialEq)]
pub struct MpPhrReport {
    pub ue_id: u32,
    pub timestamp_ms: u64,
    pub active_panels_bitmap: u8,
    pub panels: Vec<MpPhrPanelEntry>,
}

impl MpPhrReport {
    /// Serializes MP-PHR report into binary wire format with CRC-16 checksum.
    pub fn encode_wire(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(18 + self.panels.len() * 10);
        buf.extend_from_slice(&MP_PHR_WIRE_MAGIC);
        buf.extend_from_slice(&self.ue_id.to_be_bytes());
        buf.extend_from_slice(&self.timestamp_ms.to_be_bytes());
        buf.push(self.active_panels_bitmap);
        buf.push(self.panels.len() as u8);

        for p in &self.panels {
            buf.push(p.panel_id);
            buf.extend_from_slice(&p.ph_db.to_bits().to_be_bytes());
            buf.extend_from_slice(&p.p_cmax_p_dbm.to_bits().to_be_bytes());
            buf.push(if p.mpe_applied { 1 } else { 0 });
        }

        let crc = compute_crc16(&buf);
        buf.extend_from_slice(&crc.to_be_bytes());
        buf
    }

    /// Deserializes MP-PHR report from binary wire format, verifying CRC-16 integrity.
    pub fn decode_wire(data: &[u8]) -> Result<Self, StxpError> {
        if data.len() < 20 {
            return Err(StxpError::DeserializationError("Buffer too small for MP-PHR header".into()));
        }

        let payload_len = data.len() - 2;
        let expected_crc = u16::from_be_bytes([data[payload_len], data[payload_len + 1]]);
        let calculated_crc = compute_crc16(&data[..payload_len]);
        if expected_crc != calculated_crc {
            return Err(StxpError::ChecksumMismatch {
                expected: expected_crc,
                calculated: calculated_crc,
            });
        }

        if &data[0..4] != &MP_PHR_WIRE_MAGIC {
            return Err(StxpError::DeserializationError("Invalid MP-PHR wire magic header".into()));
        }

        let ue_id = u32::from_be_bytes(data[4..8].try_into().unwrap());
        let timestamp_ms = u64::from_be_bytes(data[8..16].try_into().unwrap());
        let active_panels_bitmap = data[16];
        let num_panels = data[17] as usize;

        if data.len() != 18 + num_panels * 10 + 2 {
            return Err(StxpError::DeserializationError("Payload size does not match panel count".into()));
        }

        let mut offset = 18;
        let mut panels = Vec::with_capacity(num_panels);
        for _ in 0..num_panels {
            let panel_id = data[offset];
            let ph_db = f32::from_bits(u32::from_be_bytes(data[offset + 1..offset + 5].try_into().unwrap()));
            let p_cmax_p_dbm = f32::from_bits(u32::from_be_bytes(data[offset + 5..offset + 9].try_into().unwrap()));
            let mpe_applied = data[offset + 9] != 0;
            offset += 10;
            panels.push(MpPhrPanelEntry {
                panel_id,
                ph_db,
                p_cmax_p_dbm,
                mpe_applied,
            });
        }

        Ok(Self {
            ue_id,
            timestamp_ms,
            active_panels_bitmap,
            panels,
        })
    }
}

/// Operational telemetry metrics for multi-panel transmission performance.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MultiPanelTelemetry {
    pub total_slots_scheduled: u64,
    pub single_panel_slots: u64,
    pub multi_panel_slots: u64,
    pub power_scaled_slots: u64,
    pub mpe_throttled_slots: u64,
    pub total_requested_energy_mw_slots: f64,
    pub total_transmitted_energy_mw_slots: f64,
    pub throughput_boost_accum: f64,
}

impl MultiPanelTelemetry {
    /// Percentage of slots that operated in simultaneous multi-panel transmission mode.
    pub fn stxp_utilization_percent(&self) -> f64 {
        if self.total_slots_scheduled == 0 {
            0.0
        } else {
            (self.multi_panel_slots as f64 / self.total_slots_scheduled as f64) * 100.0
        }
    }

    /// Average spatial multiplexing throughput gain over single-panel transmission.
    pub fn average_throughput_boost_ratio(&self) -> f64 {
        if self.multi_panel_slots == 0 {
            1.0
        } else {
            1.0 + (self.throughput_boost_accum / self.multi_panel_slots as f64)
        }
    }
}

/// Errors occurring during STxP scheduling and configuration.
#[derive(Debug, Clone, PartialEq)]
pub enum StxpError {
    PanelNotFound(u8),
    PanelCapacityExceeded { max: usize, attempted: usize },
    DuplicatePanelId(u8),
    PanelUnavailable(u8),
    IsolationTooLow { isolation_db: f64, required_db: f64 },
    ChecksumMismatch { expected: u16, calculated: u16 },
    DeserializationError(String),
    InvalidState(String),
}

impl fmt::Display for StxpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StxpError::PanelNotFound(id) => write!(f, "Panel ID {} not found", id),
            StxpError::PanelCapacityExceeded { max, attempted } => {
                write!(f, "Panel capacity exceeded: max {}, attempted {}", max, attempted)
            }
            StxpError::DuplicatePanelId(id) => write!(f, "Duplicate panel ID: {}", id),
            StxpError::PanelUnavailable(id) => write!(f, "Panel ID {} is currently unavailable for TX", id),
            StxpError::IsolationTooLow { isolation_db, required_db } => write!(
                f,
                "Inter-panel isolation {:.1} dB is below required {:.1} dB",
                isolation_db, required_db
            ),
            StxpError::ChecksumMismatch { expected, calculated } => write!(
                f,
                "CRC-16 mismatch: expected 0x{:04X}, calculated 0x{:04X}",
                expected, calculated
            ),
            StxpError::DeserializationError(msg) => write!(f, "Deserialization failed: {}", msg),
            StxpError::InvalidState(msg) => write!(f, "Invalid state: {}", msg),
        }
    }
}

impl std::error::Error for StxpError {}

// ---------------------------------------------------------------------------
// Central Multi-Panel STxP Engine
// ---------------------------------------------------------------------------

/// 3GPP Rel-18/19 Multi-Panel Simultaneous Transmission (STxP) Engine.
pub struct NrMultiPanelStxpEngine {
    p_cmax_total_dbm: f64,
    panels: Vec<AntennaPanelConfig>,
    panel_states: [PanelState; MAX_STXP_PANELS],
    tpc_accumulators: [f64; MAX_STXP_PANELS],
    p_mpr_db: [f64; MAX_STXP_PANELS],
    sar_dose_rolling: [f64; MAX_STXP_PANELS],
    inter_panel_isolation_db: f64,
    telemetry: MultiPanelTelemetry,
}

impl NrMultiPanelStxpEngine {
    /// Creates a new STxP Engine with specified total maximum transmission power limit.
    pub fn new(p_cmax_total_dbm: f64) -> Self {
        Self {
            p_cmax_total_dbm: p_cmax_total_dbm.clamp(0.0, 33.0),
            panels: Vec::with_capacity(MAX_STXP_PANELS),
            panel_states: [PanelState::Standby; MAX_STXP_PANELS],
            tpc_accumulators: [0.0; MAX_STXP_PANELS],
            p_mpr_db: [0.0; MAX_STXP_PANELS],
            sar_dose_rolling: [0.0; MAX_STXP_PANELS],
            inter_panel_isolation_db: 20.0,
            telemetry: MultiPanelTelemetry::default(),
        }
    }

    pub fn p_cmax_total_dbm(&self) -> f64 {
        self.p_cmax_total_dbm
    }

    pub fn inter_panel_isolation_db(&self) -> f64 {
        self.inter_panel_isolation_db
    }

    pub fn set_inter_panel_isolation_db(&mut self, val_db: f64) {
        self.inter_panel_isolation_db = val_db;
    }

    pub fn telemetry(&self) -> &MultiPanelTelemetry {
        &self.telemetry
    }

    // -----------------------------------------------------------------------
    // Panel Management
    // -----------------------------------------------------------------------

    /// Adds and activates an antenna panel in the engine.
    pub fn add_panel(&mut self, config: AntennaPanelConfig) -> Result<(), StxpError> {
        if self.panels.iter().any(|p| p.panel_id == config.panel_id) {
            return Err(StxpError::DuplicatePanelId(config.panel_id));
        }
        if self.panels.len() >= MAX_STXP_PANELS {
            return Err(StxpError::PanelCapacityExceeded {
                max: MAX_STXP_PANELS,
                attempted: self.panels.len() + 1,
            });
        }

        let id = config.panel_id as usize;
        if id < MAX_STXP_PANELS {
            self.panel_states[id] = PanelState::Active;
            self.tpc_accumulators[id] = 0.0;
            self.p_mpr_db[id] = 0.0;
            self.sar_dose_rolling[id] = 0.0;
        }

        self.panels.push(config);
        Ok(())
    }

    /// Sets the operational lifecycle state of an antenna panel.
    pub fn set_panel_state(&mut self, panel_id: u8, state: PanelState) -> Result<(), StxpError> {
        if !self.panels.iter().any(|p| p.panel_id == panel_id) {
            return Err(StxpError::PanelNotFound(panel_id));
        }
        let id = panel_id as usize;
        if id < MAX_STXP_PANELS {
            self.panel_states[id] = state;
        }
        Ok(())
    }

    /// Gets the current state of a panel.
    pub fn panel_state(&self, panel_id: u8) -> Result<PanelState, StxpError> {
        if !self.panels.iter().any(|p| p.panel_id == panel_id) {
            return Err(StxpError::PanelNotFound(panel_id));
        }
        let id = panel_id as usize;
        if id < MAX_STXP_PANELS {
            Ok(self.panel_states[id])
        } else {
            Err(StxpError::PanelNotFound(panel_id))
        }
    }

    // -----------------------------------------------------------------------
    // Maximum Permissible Exposure (MPE) & SAR Management
    // -----------------------------------------------------------------------

    /// Informs the engine of human proximity sensor reading on an antenna panel,
    /// triggering regulatory P-MPR power backoff if proximity threshold is breached.
    pub fn update_proximity_sensor(
        &mut self,
        panel_id: u8,
        distance_cm: f64,
        sar_rate_w_kg: f64,
    ) -> Result<f64, StxpError> {
        if !self.panels.iter().any(|p| p.panel_id == panel_id) {
            return Err(StxpError::PanelNotFound(panel_id));
        }
        let id = panel_id as usize;
        if id >= MAX_STXP_PANELS {
            return Err(StxpError::PanelNotFound(panel_id));
        }

        // Distance < 5.0 cm triggers MPE power management reduction
        let p_mpr = if distance_cm < 2.0 {
            // Very close proximity: up to 6 dB power reduction
            6.0
        } else if distance_cm < 5.0 {
            // Medium proximity: 3 dB power reduction
            3.0
        } else {
            0.0
        };

        self.p_mpr_db[id] = p_mpr;
        self.sar_dose_rolling[id] = (self.sar_dose_rolling[id] * 0.9) + (sar_rate_w_kg * 0.1);

        if self.sar_dose_rolling[id] > REGULATORY_SAR_LIMIT_W_KG {
            // Severe SAR violation: force panel shutdown or severe throttling
            self.panel_states[id] = PanelState::MpeThrottled;
        } else if p_mpr > 0.0 {
            self.panel_states[id] = PanelState::MpeThrottled;
        } else if self.panel_states[id] == PanelState::MpeThrottled {
            self.panel_states[id] = PanelState::Active;
        }

        Ok(p_mpr)
    }

    // -----------------------------------------------------------------------
    // Power Control Calculations
    // -----------------------------------------------------------------------

    /// Calculates independent open-loop and closed-loop transmit power for a panel (TS 38.213 §7.1.1).
    pub fn calculate_panel_target_power(
        &mut self,
        request: &PanelTransmissionRequest,
    ) -> Result<f64, StxpError> {
        let panel_cfg = self
            .panels
            .iter()
            .find(|p| p.panel_id == request.panel_id)
            .ok_or(StxpError::PanelNotFound(request.panel_id))?;

        let id = request.panel_id as usize;
        if id >= MAX_STXP_PANELS || !self.panel_states[id].is_available_for_tx() {
            return Err(StxpError::PanelUnavailable(request.panel_id));
        }

        // Update closed-loop TPC accumulator
        self.tpc_accumulators[id] += request.tpc_command_db;
        let f_i = self.tpc_accumulators[id];

        // Bandwidth allocation component: 10 * log10(2^mu * M_RB)
        let m_rb = request.allocated_prbs.max(1) as f64;
        let bw_comp = 10.0 * m_rb.log10();

        // Pathloss compensation component: alpha * PL
        let pl_comp = panel_cfg.alpha * request.pathloss_db;

        // Raw open-loop + closed-loop nominal power
        let p_nominal = panel_cfg.p_o_pusch_dbm + bw_comp + pl_comp + request.delta_tf_db + f_i;

        // Effective panel cap: P_CMAX,p - P-MPR
        let p_cmax_eff = panel_cfg.p_cmax_p_dbm - self.p_mpr_db[id];

        // Clamp power between MIN_PANEL_POWER_DBM and p_cmax_eff
        let p_target = p_nominal.clamp(MIN_PANEL_POWER_DBM, p_cmax_eff);
        Ok(p_target)
    }

    // -----------------------------------------------------------------------
    // STxP Slot Scheduling & Priority-Based Total Power Scaling
    // -----------------------------------------------------------------------

    /// Evaluates and schedules simultaneous multi-panel uplink transmission for a slot.
    pub fn evaluate_stxp_slot(
        &mut self,
        requests: &[PanelTransmissionRequest],
        slot_number: u32,
    ) -> Result<StxpSchedulingResult, StxpError> {
        self.telemetry.total_slots_scheduled += 1;

        if requests.is_empty() {
            return Ok(StxpSchedulingResult {
                slot_number,
                tx_case: None,
                total_requested_power_mw: 0.0,
                total_transmitted_power_mw: 0.0,
                p_cmax_total_mw: dbm_to_mw(self.p_cmax_total_dbm),
                power_scaled: false,
                decisions: Vec::new(),
            });
        }

        // Check inter-panel isolation if more than 1 panel is requesting transmission
        if requests.len() > 1 && self.inter_panel_isolation_db < MIN_INTER_PANEL_ISOLATION_DB {
            return Err(StxpError::IsolationTooLow {
                isolation_db: self.inter_panel_isolation_db,
                required_db: MIN_INTER_PANEL_ISOLATION_DB,
            });
        }

        // Step 1: Calculate target transmit power per panel
        let mut temp_decisions = Vec::with_capacity(requests.len());
        for req in requests {
            let target_dbm = self.calculate_panel_target_power(req)?;
            let id = req.panel_id as usize;
            let mpe_reduction = if id < MAX_STXP_PANELS { self.p_mpr_db[id] } else { 0.0 };

            temp_decisions.push((
                req.panel_id,
                req.channel_type,
                target_dbm,
                dbm_to_mw(target_dbm),
                mpe_reduction,
                req.channel_type.priority_rank(),
            ));
        }

        let total_requested_mw: f64 = temp_decisions.iter().map(|d| d.3).sum();
        let p_cmax_total_mw = dbm_to_mw(self.p_cmax_total_dbm);

        let mut power_scaled = false;
        let mut final_decisions = Vec::with_capacity(temp_decisions.len());

        // Step 2: Cross-panel total power scaling if sum exceeds P_CMAX,total (TS 38.213 §7.5)
        if total_requested_mw > p_cmax_total_mw {
            power_scaled = true;
            self.telemetry.power_scaled_slots += 1;

            // Sort requests by priority rank (ascending: 0 is highest)
            let mut indices: Vec<usize> = (0..temp_decisions.len()).collect();
            indices.sort_by_key(|&idx| temp_decisions[idx].5);

            let mut remaining_power_mw = p_cmax_total_mw;
            let mut scaled_powers_mw = vec![0.0; temp_decisions.len()];

            // Allocate power to higher priority channels first
            let mut i = 0;
            while i < indices.len() {
                // Group channels with identical priority
                let curr_rank = temp_decisions[indices[i]].5;
                let mut j = i;
                let mut group_requested_mw = 0.0;
                while j < indices.len() && temp_decisions[indices[j]].5 == curr_rank {
                    group_requested_mw += temp_decisions[indices[j]].3;
                    j += 1;
                }

                if remaining_power_mw >= group_requested_mw {
                    // Full power for this priority group
                    for k in i..j {
                        scaled_powers_mw[indices[k]] = temp_decisions[indices[k]].3;
                    }
                    remaining_power_mw -= group_requested_mw;
                } else if remaining_power_mw > 0.0 {
                    // Proportionally scale remaining channels in this priority group
                    let scale = remaining_power_mw / group_requested_mw;
                    for k in i..j {
                        scaled_powers_mw[indices[k]] = temp_decisions[indices[k]].3 * scale;
                    }
                    remaining_power_mw = 0.0;
                } else {
                    // Lower priority channels drop to 0
                    for k in i..j {
                        scaled_powers_mw[indices[k]] = 0.0;
                    }
                }

                i = j;
            }

            for idx in 0..temp_decisions.len() {
                let (pid, ch, req_dbm, req_mw, mpe_db, _) = temp_decisions[idx];
                let allocated_mw = scaled_powers_mw[idx];
                let scaling_factor = if req_mw > 0.0 { allocated_mw / req_mw } else { 0.0 };
                let scaled_dbm = mw_to_dbm(allocated_mw);

                final_decisions.push(PanelTransmissionDecision {
                    panel_id: pid,
                    channel_type: ch,
                    requested_power_dbm: req_dbm,
                    scaled_power_dbm: scaled_dbm,
                    scaling_factor,
                    p_mpr_db: mpe_db,
                    allocated: allocated_mw > 1e-6,
                });
            }
        } else {
            // No total power scaling needed
            for (pid, ch, req_dbm, _, mpe_db, _) in temp_decisions {
                final_decisions.push(PanelTransmissionDecision {
                    panel_id: pid,
                    channel_type: ch,
                    requested_power_dbm: req_dbm,
                    scaled_power_dbm: req_dbm,
                    scaling_factor: 1.0,
                    p_mpr_db: mpe_db,
                    allocated: true,
                });
            }
        }

        let total_transmitted_mw: f64 = final_decisions
            .iter()
            .map(|d| if d.allocated { dbm_to_mw(d.scaled_power_dbm) } else { 0.0 })
            .sum();

        // Classify STxP transmission case
        let active_allocated_count = final_decisions.iter().filter(|d| d.allocated).count();
        let tx_case = if active_allocated_count > 1 {
            self.telemetry.multi_panel_slots += 1;
            // Calculate spatial multiplexing throughput gain
            self.telemetry.throughput_boost_accum += (active_allocated_count as f64 - 1.0) * 0.85;

            let has_pusch = final_decisions
                .iter()
                .any(|d| d.allocated && matches!(d.channel_type, UlChannelType::PuschData | UlChannelType::PuschHarqAck));
            let has_pucch = final_decisions
                .iter()
                .any(|d| d.allocated && matches!(d.channel_type, UlChannelType::PucchHarqAck | UlChannelType::PucchCsi));
            let has_srs = final_decisions
                .iter()
                .any(|d| d.allocated && matches!(d.channel_type, UlChannelType::Srs));

            if has_pusch && has_pucch {
                Some(StxpTransmissionCase::SimultaneousPuschPucch)
            } else if has_pusch && has_srs {
                Some(StxpTransmissionCase::SimultaneousPuschSrs)
            } else if has_pucch && !has_pusch {
                Some(StxpTransmissionCase::SimultaneousPucchPucch)
            } else {
                Some(StxpTransmissionCase::SimultaneousPuschMtrp)
            }
        } else {
            self.telemetry.single_panel_slots += 1;
            None
        };

        if final_decisions.iter().any(|d| d.p_mpr_db > 0.0) {
            self.telemetry.mpe_throttled_slots += 1;
        }

        self.telemetry.total_requested_energy_mw_slots += total_requested_mw;
        self.telemetry.total_transmitted_energy_mw_slots += total_transmitted_mw;

        Ok(StxpSchedulingResult {
            slot_number,
            tx_case,
            total_requested_power_mw: total_requested_mw,
            total_transmitted_power_mw: total_transmitted_mw,
            p_cmax_total_mw,
            power_scaled,
            decisions: final_decisions,
        })
    }

    // -----------------------------------------------------------------------
    // Rel-18 Multi-Panel Power Headroom Report (MP-PHR) Generation
    // -----------------------------------------------------------------------

    /// Generates the 3GPP Rel-18 Multi-Panel Power Headroom Report (MP-PHR) MAC CE.
    pub fn generate_mp_phr_report(
        &self,
        ue_id: u32,
        timestamp_ms: u64,
    ) -> Result<MpPhrReport, StxpError> {
        let mut active_bitmap = 0u8;
        let mut panel_entries = Vec::with_capacity(self.panels.len());

        for p in &self.panels {
            let id = p.panel_id as usize;
            if id < MAX_STXP_PANELS && self.panel_states[id].is_available_for_tx() {
                active_bitmap |= 1 << p.panel_id;

                let p_cmax_eff = p.p_cmax_p_dbm - self.p_mpr_db[id];
                // Nominal power with zero pathloss/adjustment as baseline reference
                let p_nominal_ref = p.p_o_pusch_dbm + self.tpc_accumulators[id];
                let ph_db = (p_cmax_eff - p_nominal_ref).clamp(-23.0, 40.0) as f32;

                panel_entries.push(MpPhrPanelEntry {
                    panel_id: p.panel_id,
                    ph_db,
                    p_cmax_p_dbm: p_cmax_eff as f32,
                    mpe_applied: self.p_mpr_db[id] > 0.0,
                });
            }
        }

        Ok(MpPhrReport {
            ue_id,
            timestamp_ms,
            active_panels_bitmap: active_bitmap,
            panels: panel_entries,
        })
    }
}

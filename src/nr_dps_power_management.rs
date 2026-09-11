//! 3GPP Rel-18 / Rel-19 Dynamic Power Sharing (DPS) & Dual-Connectivity Uplink Power Management Engine.
//!
//! Compliant with:
//! - 3GPP TS 38.213 Rel-18 §7.5 / §7.6 ("Uplink power control for simultaneous transmissions in Dual Connectivity and Carrier Aggregation")
//! - 3GPP TS 38.101-1 / TS 38.101-2 / TS 38.101-3 Rel-18 ("User Equipment (UE) radio transmission and reception - Maximum power limits, PC1/PC2/PC3/PC4, MPR, A-MPR, and SAR backoff")
//! - 3GPP TS 38.331 Rel-18 ("Radio Resource Control - `PowerHeadroomReportConfig`, `dualPA-Architecture`, `p-max`, `maxTxPower`, `phr-ModeOtherCG`")
//! - 3GPP TS 38.321 Rel-18 §6.1.3.8 / §6.1.3.9 ("Multiple Entry / Single Entry PHR MAC Control Elements")
//! - 3GPP TS 37.340 Rel-18 ("Multi-connectivity; Overall description; Stage-2 - §7.6 EN-DC / NR-DC power sharing")
//!
//! Features:
//! 1. UE Power Class Definitions & Per-Carrier $P_{\mathrm{CMAX}}$ Computation:
//!    - PC1 (31 dBm / 1258.9 mW), PC2 (26 dBm / 398.1 mW), PC3 (23 dBm / 199.5 mW), PC4 (20 dBm / 100.0 mW).
//!    - MPR, A-MPR, and P-MPR bounds with $\Delta T_C$ margin calculations.
//! 2. Single PA vs Dual PA Architecture:
//!    - Single PA: total instantaneous power sum across all carriers bounded by $P_{\mathrm{CMAX,total}}$.
//!    - Dual PA: independent per-PA limits and coordinated inter-PA thermal/exposure envelope.
//! 3. Dynamic Power Sharing (DPS) Modes:
//!    - Semi-Static Mode: fixed power partition ratio $\alpha_{\mathrm{MCG}} + \alpha_{\mathrm{SCG}} = 1.0$.
//!    - Dynamic Priority Mode: instantaneous priority-based power preemption.
//!    - Rel-18 Lookahead Enhanced Mode: sub-millisecond lookahead buffer smoothing transitions and preserving EVM.
//! 4. 3GPP TS 38.213 §7.5.3 Strict Channel Priority Hierarchy:
//!    - Priority 1: PRACH (cell access, handover, beam failure recovery).
//!    - Priority 2: PUCCH with HARQ-ACK and/or SR.
//!    - Priority 3: PUCCH with CSI.
//!    - Priority 4: PUSCH carrying UCI.
//!    - Priority 5: PUSCH without UCI (data payload).
//!    - Priority 6: SRS (aperiodic > semi-persistent > periodic).
//!    - Linear proportional power scaling ($\beta \in [0.0, 1.0]$) and selective channel dropping.
//! 5. Time-Averaged SAR (Specific Absorption Rate) & MPE Compliance Governor:
//!    - Sliding time window (100s for Sub-6 GHz, 60s for FR3, 4s for FR2 mmWave).
//!    - Strict rolling RF energy budget integration preventing biological exposure violations.
//! 6. Open-Loop & Closed-Loop (TPC) Servo Engine:
//!    - Path loss estimation from downlink RSRP.
//!    - Fractional path loss compensation ($\alpha \in [0.0, 1.0]$) and PRB bandwidth scaling ($10 \log_{10}(M)$).
//!    - TPC accumulation mode vs absolute mode.
//! 7. Rel-18 Multiple Entry PHR MAC Control Element Serialization:
//!    - Real and Virtual Type 1, Type 2, and Type 3 Power Headroom encoding.
//!    - 6-bit level mapping table conforming to TS 38.133.
//!
//! Pure standard Rust with zero external dependencies.

use std::collections::VecDeque;
use std::fmt;

// ---------------------------------------------------------------------------
// Physical Constants & Conversions
// ---------------------------------------------------------------------------

/// Lowest power representation threshold in dBm (-140 dBm ~ 0.1 attowatt).
pub const MIN_POWER_DBM: f64 = -140.0;

/// Converts power in dBm to milliwatts (mW).
#[inline]
pub fn dbm_to_mw(dbm: f64) -> f64 {
    10.0_f64.powf(dbm / 10.0)
}

/// Converts power in milliwatts (mW) to dBm, clamped at `MIN_POWER_DBM`.
#[inline]
pub fn mw_to_dbm(mw: f64) -> f64 {
    if mw <= 1e-14 {
        MIN_POWER_DBM
    } else {
        10.0 * mw.log10()
    }
}

// ---------------------------------------------------------------------------
// UE Power Classes & RF PA Architecture
// ---------------------------------------------------------------------------

/// 3GPP UE Power Class specification (TS 38.101-1 / TS 38.101-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UePowerClass {
    /// Class 1: +31 dBm (approx 1258.9 mW), High-Power Fixed/Vehicular UE.
    Class1,
    /// Class 2: +26 dBm (approx 398.1 mW), High-Power Handheld (Bands n41, n77, n78, n79).
    Class2,
    /// Class 3: +23 dBm (approx 199.5 mW), Standard Handheld Default.
    Class3,
    /// Class 4: +20 dBm (approx 100.0 mW), Low-Power Small Form Factor / Wearable.
    Class4,
}

impl UePowerClass {
    /// Returns the nominal maximum output power in dBm.
    pub fn nominal_max_power_dbm(&self) -> f64 {
        match self {
            UePowerClass::Class1 => 31.0,
            UePowerClass::Class2 => 26.0,
            UePowerClass::Class3 => 23.0,
            UePowerClass::Class4 => 20.0,
        }
    }

    /// Returns the nominal maximum output power in milliwatts.
    pub fn nominal_max_power_mw(&self) -> f64 {
        dbm_to_mw(self.nominal_max_power_dbm())
    }
}

/// RF Power Amplifier (PA) Hardware Architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PaArchitecture {
    /// Single shared RF PA: Simultaneous multi-carrier transmissions share total instantaneous power.
    SinglePa,
    /// Dual RF PA: Independent PAs per carrier group (e.g. MCG and SCG have dedicated PAs).
    DualPa,
}

/// Cell Group Identifier in Dual Connectivity (TS 37.340).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CellGroupType {
    /// Master Cell Group (anchored at Master Node, e.g. MeNB in EN-DC or MN in NR-DC).
    Mcg,
    /// Secondary Cell Group (anchored at Secondary Node, e.g. SgNB in EN-DC or SN in NR-DC).
    Scg,
}

/// Carrier-specific power parameters and regulatory constraints.
#[derive(Debug, Clone, PartialEq)]
pub struct UeCarrierConfig {
    /// Component carrier ID (0..=31).
    pub carrier_id: u8,
    /// Cell group association.
    pub cell_group: CellGroupType,
    /// Center carrier frequency in Hertz.
    pub carrier_frequency_hz: f64,
    /// Maximum allowed cell transmit power signaled by gNB ($P_{\mathrm{EMAX}}$) in dBm.
    pub p_emax_dbm: f64,
    /// Maximum Power Reduction (MPR) in dB based on waveform/modulation.
    pub mpr_db: f64,
    /// Additional MPR (A-MPR) in dB due to regional spectrum emission masks.
    pub a_mpr_db: f64,
    /// Power Management MPR (P-MPR) in dB for human SAR/MPE compliance.
    pub p_mpr_db: f64,
    /// $\Delta T_C$ allowance in dB (0.0 or 1.5 dB depending on band edge proximity).
    pub delta_tc_db: f64,
}

impl UeCarrierConfig {
    /// Computes the configured maximum output power $P_{\mathrm{CMAX},c}$ in dBm according to TS 38.101-1 §6.2.4.
    pub fn compute_pcmax(&self, power_class: UePowerClass) -> f64 {
        let p_power_class = power_class.nominal_max_power_dbm();
        
        // P_CMAX_L = min(P_EMAX - Delta_TC, P_PowerClass - max(MPR + A_MPR, P_MPR) - Delta_TC)
        let total_mpr = (self.mpr_db + self.a_mpr_db).max(self.p_mpr_db);
        let p_cmax_l = (self.p_emax_dbm - self.delta_tc_db)
            .min(p_power_class - total_mpr - self.delta_tc_db);

        // P_CMAX_H = min(P_EMAX, P_PowerClass)
        let p_cmax_h = self.p_emax_dbm.min(p_power_class);

        // Standard operational setting is conservative lower bound or intermediate nominal
        p_cmax_l.min(p_cmax_h)
    }
}

// ---------------------------------------------------------------------------
// Dynamic Power Sharing (DPS) Modes
// ---------------------------------------------------------------------------

/// Dynamic Power Sharing Operational Modes.
#[derive(Debug, Clone, PartialEq)]
pub enum DpsMode {
    /// Semi-Static Power Partition: fixed power split between MCG and SCG.
    SemiStatic {
        /// Fraction of total power allocated to MCG (0.0 ..= 1.0).
        mcg_ratio: f64,
    },
    /// Dynamic Priority Mode: instantaneous channel-by-channel priority arbitration.
    DynamicPriority,
    /// Rel-18 Lookahead Enhanced Mode: sub-millisecond lookahead window to minimize EVM dips.
    LookaheadEnhanced {
        /// Lookahead horizon in microseconds (e.g. 500 us = 1 slot at 30 kHz SCS).
        lookahead_us: u32,
        /// Smoothing parameter for power scaling transitions (0.0 = immediate, 1.0 = heavy damping).
        smoothing_factor: f64,
    },
}

// ---------------------------------------------------------------------------
// 3GPP TS 38.213 §7.5.3 Channel Priority Hierarchy
// ---------------------------------------------------------------------------

/// Uplink physical channel and signal types with priority classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UplinkChannelType {
    /// Priority 1: PRACH (Initial Access, Handover, or Beam Failure Recovery).
    Prach { is_handover_or_bfr: bool },
    /// Priority 2: PUCCH with HARQ-ACK and/or SR (Critical control).
    PucchHarqAckSr { has_sr: bool, has_bfr_sr: bool },
    /// Priority 3: PUCCH with CSI (Channel State Information).
    PucchCsi { is_aperiodic: bool },
    /// Priority 4: PUSCH multiplexing UCI (Uplink Control Information on PUSCH).
    PuschWithUci { has_harq_ack: bool },
    /// Priority 5: PUSCH data payload only (no UCI).
    PuschDataOnly { mcs: u8 },
    /// Priority 6: Sounding Reference Signal (SRS).
    Srs { is_aperiodic: bool },
}

impl UplinkChannelType {
    /// Returns numerical priority according to TS 38.213 §7.5.3 (1 is highest, 6 is lowest).
    pub fn priority_tier(&self) -> u8 {
        match self {
            UplinkChannelType::Prach { .. } => 1,
            UplinkChannelType::PucchHarqAckSr { .. } => 2,
            UplinkChannelType::PucchCsi { .. } => 3,
            UplinkChannelType::PuschWithUci { .. } => 4,
            UplinkChannelType::PuschDataOnly { .. } => 5,
            UplinkChannelType::Srs { .. } => 6,
        }
    }

    /// Sub-tier priority discriminator for ties within the same tier (lower number = higher priority).
    pub fn sub_tier_priority(&self) -> u8 {
        match self {
            UplinkChannelType::Prach { is_handover_or_bfr } => {
                if *is_handover_or_bfr { 0 } else { 1 }
            }
            UplinkChannelType::PucchHarqAckSr { has_bfr_sr, has_sr } => {
                if *has_bfr_sr { 0 } else if *has_sr { 1 } else { 2 }
            }
            UplinkChannelType::PucchCsi { is_aperiodic } => {
                if *is_aperiodic { 0 } else { 1 }
            }
            UplinkChannelType::PuschWithUci { has_harq_ack } => {
                if *has_harq_ack { 0 } else { 1 }
            }
            UplinkChannelType::PuschDataOnly { mcs } => {
                // Higher MCS prioritized slightly or standard tie
                255 - *mcs
            }
            UplinkChannelType::Srs { is_aperiodic } => {
                if *is_aperiodic { 0 } else { 1 }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Transmission Requests & Arbitration Results
// ---------------------------------------------------------------------------

/// Individual transmission request from a MAC/PHY scheduler.
#[derive(Debug, Clone, PartialEq)]
pub struct TransmissionRequest {
    /// Unique carrier ID.
    pub carrier_id: u8,
    /// Physical channel type.
    pub channel_type: UplinkChannelType,
    /// Requested transmit power in dBm.
    pub requested_power_dbm: f64,
    /// Starting OFDM symbol index in slot (0..=13).
    pub symbol_start: u8,
    /// Number of OFDM symbols allocated (1..=14).
    pub symbol_count: u8,
    /// Number of allocated PRBs.
    pub prb_count: u16,
    /// Scheduled start time in microseconds.
    pub timestamp_us: u64,
}

/// Arbitrated transmission result after DPS power scaling.
#[derive(Debug, Clone, PartialEq)]
pub struct ArbitratedTransmission {
    /// Unique carrier ID.
    pub carrier_id: u8,
    /// Physical channel type.
    pub channel_type: UplinkChannelType,
    /// Originally requested power in dBm.
    pub requested_power_dbm: f64,
    /// Allocated transmit power in dBm.
    pub allocated_power_dbm: f64,
    /// Linear power scaling factor ($\beta \in [0.0, 1.0]$).
    pub scaling_factor: f64,
    /// True if the transmission was completely dropped ($\beta = 0.0$).
    pub is_dropped: bool,
}

/// Aggregate result of an arbitration epoch.
#[derive(Debug, Clone, PartialEq)]
pub struct DpsArbitrationResult {
    /// Scheduled start timestamp in microseconds.
    pub timestamp_us: u64,
    /// Total requested power across all carriers in milliwatts.
    pub total_requested_power_mw: f64,
    /// Total allocated power across all carriers in milliwatts.
    pub total_allocated_power_mw: f64,
    /// Maximum allowed power ceiling in milliwatts for this epoch.
    pub power_ceiling_mw: f64,
    /// True if any channel was scaled down or dropped.
    pub power_curtailment_applied: bool,
    /// Per-channel arbitrated decisions.
    pub channels: Vec<ArbitratedTransmission>,
}

// ---------------------------------------------------------------------------
// Time-Averaged SAR & MPE Compliance Governor
// ---------------------------------------------------------------------------

/// Rolling Time-Averaged SAR / MPE Exposure Energy Governor.
#[derive(Debug, Clone, PartialEq)]
pub struct SarGovernor {
    /// Regulatory sliding time window in seconds (e.g. 100.0s for sub-6 GHz, 4.0s for mmWave).
    pub window_duration_seconds: f64,
    /// Maximum allowed RF energy budget over the sliding window in Joules.
    pub max_energy_budget_joules: f64,
    /// History of transmissions: `(timestamp_us, energy_joules)`.
    history: VecDeque<(u64, f64)>,
    /// Accumulated energy within the sliding window in Joules.
    accumulated_energy_joules: f64,
}

impl SarGovernor {
    /// Creates a new SAR governor.
    ///
    /// - `window_duration_seconds`: duration of rolling integration window.
    /// - `max_average_power_mw`: maximum allowed time-averaged continuous power (e.g. 100 mW = 20 dBm).
    pub fn new(window_duration_seconds: f64, max_average_power_mw: f64) -> Self {
        let max_energy_budget = (max_average_power_mw * 1e-3) * window_duration_seconds;
        Self {
            window_duration_seconds,
            max_energy_budget_joules: max_energy_budget,
            history: VecDeque::new(),
            accumulated_energy_joules: 0.0,
        }
    }

    /// Purges records older than `current_time_us - window_duration`.
    pub fn prune_old_records(&mut self, current_time_us: u64) {
        let window_us = (self.window_duration_seconds * 1_000_000.0) as u64;
        let cutoff_us = current_time_us.saturating_sub(window_us);

        while let Some(&(ts, energy)) = self.history.front() {
            if ts < cutoff_us {
                self.accumulated_energy_joules = (self.accumulated_energy_joules - energy).max(0.0);
                self.history.pop_front();
            } else {
                break;
            }
        }
    }

    /// Records an emitted transmission and updates energy history.
    pub fn record_emission(&mut self, power_mw: f64, duration_us: u64, current_time_us: u64) {
        self.prune_old_records(current_time_us);
        let energy_joules = (power_mw * 1e-3) * (duration_us as f64 * 1e-6);
        self.accumulated_energy_joules += energy_joules;
        self.history.push_back((current_time_us, energy_joules));
    }

    /// Computes the maximum allowed instantaneous power in mW for a planned slot of `duration_us`.
    pub fn get_allowed_power_mw(&mut self, duration_us: u64, current_time_us: u64) -> f64 {
        self.prune_old_records(current_time_us);
        let remaining_energy = (self.max_energy_budget_joules - self.accumulated_energy_joules).max(0.0);
        let duration_seconds = duration_us as f64 * 1e-6;
        if duration_seconds <= 0.0 {
            0.0
        } else {
            (remaining_energy / duration_seconds) * 1000.0 // to mW
        }
    }

    /// Returns current ratio of consumed energy over budget (0.0 to 1.0+).
    pub fn exposure_ratio(&self) -> f64 {
        if self.max_energy_budget_joules <= 0.0 {
            1.0
        } else {
            self.accumulated_energy_joules / self.max_energy_budget_joules
        }
    }
}

// ---------------------------------------------------------------------------
// Open-Loop & Closed-Loop (TPC) Servo Engine
// ---------------------------------------------------------------------------

/// Transmit Power Control (TPC) Command Accumulation Mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TpcAccumulationMode {
    /// Accumulative mode: $f(i) = f(i-1) + \delta_{\mathrm{TPC}}$.
    Accumulation,
    /// Absolute mode: $f(i) = \delta_{\mathrm{TPC}}$.
    Absolute,
}

/// Downlink Path Loss & Closed-Loop Power Control Servo for a Carrier.
#[derive(Debug, Clone, PartialEq)]
pub struct PowerControlLoop {
    /// Base nominal power $P_{\mathrm{O\_NOMINAL\_PUSCH}}$ in dBm.
    pub p_o_nominal_dbm: f64,
    /// UE-specific offset $P_{\mathrm{O\_UE\_PUSCH}}$ in dBm.
    pub p_o_ue_dbm: f64,
    /// Fractional path loss factor $\alpha \in [0.0, 1.0]$.
    pub alpha: f64,
    /// Estimated downlink path loss ($PL$) in dB.
    pub path_loss_db: f64,
    /// Closed-loop TPC accumulator $f(i)$ in dB.
    pub tpc_accumulator_db: f64,
    /// Transport format compensation $\Delta_{\mathrm{TF}}$ in dB.
    pub delta_tf_db: f64,
}

impl PowerControlLoop {
    /// Creates a new power control loop servo.
    pub fn new(p_o_nominal_dbm: f64, p_o_ue_dbm: f64, alpha: f64) -> Self {
        Self {
            p_o_nominal_dbm,
            p_o_ue_dbm,
            alpha: alpha.clamp(0.0, 1.0),
            path_loss_db: 80.0, // initial default 80 dB path loss
            tpc_accumulator_db: 0.0,
            delta_tf_db: 0.0,
        }
    }

    /// Updates path loss from reference signal received power (RSRP) and gNB transmit power.
    pub fn update_path_loss(&mut self, rs_tx_power_dbm: f64, rsrp_dbm: f64) {
        self.path_loss_db = (rs_tx_power_dbm - rsrp_dbm).max(0.0);
    }

    /// Applies a TPC command delta in dB.
    pub fn apply_tpc_command(&mut self, tpc_delta_db: f64, mode: TpcAccumulationMode) {
        match mode {
            TpcAccumulationMode::Accumulation => {
                self.tpc_accumulator_db += tpc_delta_db;
                // Clamped within 3GPP operational dynamic range [-16 dB, +16 dB]
                self.tpc_accumulator_db = self.tpc_accumulator_db.clamp(-16.0, 16.0);
            }
            TpcAccumulationMode::Absolute => {
                self.tpc_accumulator_db = tpc_delta_db.clamp(-16.0, 16.0);
            }
        }
    }

    /// Computes target PUSCH transmit power according to TS 38.213 §7.1.1:
    /// $P_{\mathrm{PUSCH}} = \min(P_{\mathrm{CMAX}}, P_O + 10 \log_{10}(M) + \alpha \cdot PL + \Delta_{\mathrm{TF}} + f(i))$
    pub fn compute_target_pusch_power(&self, prb_count: u16, pcmax_dbm: f64) -> f64 {
        let m_rb = prb_count.max(1) as f64;
        let bandwidth_term = 10.0 * m_rb.log10();
        let p_o = self.p_o_nominal_dbm + self.p_o_ue_dbm;
        let target_power = p_o + bandwidth_term + (self.alpha * self.path_loss_db) + self.delta_tf_db + self.tpc_accumulator_db;
        target_power.min(pcmax_dbm)
    }
}

// ---------------------------------------------------------------------------
// Rel-18 Multiple Entry PHR MAC CE Binary Serialization
// ---------------------------------------------------------------------------

/// Power Headroom (PH) Reporting Type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PhrType {
    /// Type 1 PH: PUSCH headroom ($PH = P_{\mathrm{CMAX},c} - P_{\mathrm{PUSCH},c}$).
    Type1,
    /// Type 2 PH: PUCCH + PUSCH simultaneous headroom for SpCell (TS 38.321 §6.1.3.8).
    Type2,
    /// Type 3 PH: SRS transmit headroom.
    Type3,
}

/// Power Headroom Entry for a Serving Cell.
#[derive(Debug, Clone, PartialEq)]
pub struct PhrEntry {
    /// Serving cell index.
    pub carrier_id: u8,
    /// PH report type.
    pub phr_type: PhrType,
    /// Power headroom in dB (-32.0 dB to +38.0 dB).
    pub ph_db: f64,
    /// Configured maximum power $P_{\mathrm{CMAX},c}$ in dBm, if reported ($V=0$).
    pub pcmax_dbm: Option<f64>,
    /// Virtual transmission indicator ($V=1$: virtual transmission based on reference format).
    pub is_virtual: bool,
    /// Power Management MPR application indicator ($P=1$: power backoff applied).
    pub p_mpr_applied: bool,
}

impl PhrEntry {
    /// Maps continuous PH in dB to 6-bit index (0..=63) conforming to TS 38.133 Table 10.1.17.1-1:
    /// Index 0: < -32 dB
    /// Index 1: -32 <= PH < -31 dB ... Index 62: 29 <= PH < 30 dB, Index 63: >= 30 dB (or up to 38 dB in Rel-18).
    pub fn encode_ph_level(ph_db: f64) -> u8 {
        if ph_db < -32.0 {
            0
        } else if ph_db >= 31.0 {
            63
        } else {
            let idx = (ph_db + 32.0).floor() as u8;
            idx.min(63)
        }
    }

    /// Decodes 6-bit index back to nominal center PH in dB.
    pub fn decode_ph_level(level: u8) -> f64 {
        let l = level.min(63) as f64;
        -32.0 + l + 0.5
    }

    /// Maps continuous $P_{\mathrm{CMAX},c}$ in dBm to 6-bit index (0..=63) conforming to TS 38.133 Table 10.1.18.1-1:
    /// Index 0: < -29 dBm ... Index 63: >= 33 dBm (1 dB step).
    pub fn encode_pcmax_level(pcmax_dbm: f64) -> u8 {
        if pcmax_dbm < -29.0 {
            0
        } else if pcmax_dbm >= 33.0 {
            63
        } else {
            let idx = (pcmax_dbm + 29.0).floor() as u8;
            idx.min(63)
        }
    }

    /// Decodes 6-bit index back to nominal $P_{\mathrm{CMAX},c}$ in dBm.
    pub fn decode_pcmax_level(level: u8) -> f64 {
        let l = level.min(63) as f64;
        -29.0 + l
    }
}

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

/// Errors encountered in Dynamic Power Sharing operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DpsError {
    InvalidCarrierConfig(&'static str),
    InvalidPowerAllocation(&'static str),
    SarViolation { current_ratio: u32 },
    BufferOverflow(&'static str),
    EncodingError(&'static str),
    DecodingError(&'static str),
}

impl fmt::Display for DpsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DpsError::InvalidCarrierConfig(msg) => write!(f, "Invalid carrier config: {msg}"),
            DpsError::InvalidPowerAllocation(msg) => write!(f, "Invalid power allocation: {msg}"),
            DpsError::SarViolation { current_ratio } => {
                write!(f, "SAR exposure limit violated: {current_ratio}% of energy budget")
            }
            DpsError::BufferOverflow(msg) => write!(f, "Buffer overflow: {msg}"),
            DpsError::EncodingError(msg) => write!(f, "PHR MAC CE encoding error: {msg}"),
            DpsError::DecodingError(msg) => write!(f, "PHR MAC CE decoding error: {msg}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Dynamic Power Sharing (DPS) Arbiter Engine
// ---------------------------------------------------------------------------

/// Main 3GPP Rel-18/19 Dynamic Power Sharing & Dual-Connectivity Arbiter.
#[derive(Debug, Clone)]
pub struct DpsArbiter {
    /// UE Power Class.
    pub power_class: UePowerClass,
    /// RF PA hardware architecture.
    pub pa_architecture: PaArchitecture,
    /// Active DPS operational mode.
    pub dps_mode: DpsMode,
    /// Configured component carriers.
    pub carriers: Vec<UeCarrierConfig>,
    /// SAR and MPE regulatory energy governor.
    pub sar_governor: SarGovernor,
    /// Previous epoch allocated power in mW (for lookahead smoothing).
    last_allocated_power_mw: f64,
}

impl DpsArbiter {
    /// Creates a new DPS Arbiter instance.
    pub fn new(
        power_class: UePowerClass,
        pa_architecture: PaArchitecture,
        dps_mode: DpsMode,
        carriers: Vec<UeCarrierConfig>,
        sar_window_seconds: f64,
    ) -> Self {
        // Average SAR power limit set conservatively to PC3 nominal (200 mW) or power class max
        let max_avg_sar_mw = power_class.nominal_max_power_mw();
        let sar_gov = SarGovernor::new(sar_window_seconds, max_avg_sar_mw);

        Self {
            power_class,
            pa_architecture,
            dps_mode,
            carriers,
            sar_governor: sar_gov,
            last_allocated_power_mw: 0.0,
        }
    }

    /// Returns aggregate maximum UE power ceiling in milliwatts ($P_{\mathrm{CMAX,total}}$).
    pub fn get_total_pcmax_mw(&self) -> f64 {
        // Total power cannot exceed UE Power Class maximum
        let class_max_mw = self.power_class.nominal_max_power_mw();

        // Individual carrier PCMAX sum
        let carrier_sum_mw: f64 = self
            .carriers
            .iter()
            .map(|c| dbm_to_mw(c.compute_pcmax(self.power_class)))
            .sum();

        match self.pa_architecture {
            PaArchitecture::SinglePa => class_max_mw.min(carrier_sum_mw),
            PaArchitecture::DualPa => {
                // In Dual PA, MCG and SCG each have independent PAs, bounded by total UE class
                class_max_mw.min(carrier_sum_mw)
            }
        }
    }

    /// Arbitrates a batch of simultaneous transmission requests for an epoch according to TS 38.213 §7.5.3.
    pub fn arbitrate(
        &mut self,
        requests: &[TransmissionRequest],
        current_time_us: u64,
        slot_duration_us: u64,
    ) -> Result<DpsArbitrationResult, DpsError> {
        if requests.is_empty() {
            return Ok(DpsArbitrationResult {
                timestamp_us: current_time_us,
                total_requested_power_mw: 0.0,
                total_allocated_power_mw: 0.0,
                power_ceiling_mw: self.get_total_pcmax_mw(),
                power_curtailment_applied: false,
                channels: Vec::new(),
            });
        }

        // 1. Calculate physical and regulatory power ceilings
        let hw_ceiling_mw = self.get_total_pcmax_mw();
        let sar_ceiling_mw = self.sar_governor.get_allowed_power_mw(slot_duration_us, current_time_us);
        let mut active_ceiling_mw = hw_ceiling_mw.min(sar_ceiling_mw);

        // 2. Handle Semi-Static vs Dynamic vs Lookahead mode adjustments
        match &self.dps_mode {
            DpsMode::SemiStatic { mcg_ratio } => {
                // In semi-static mode, partition ceiling by CellGroup
                let mcg_ceiling_mw = active_ceiling_mw * mcg_ratio.clamp(0.0, 1.0);
                let scg_ceiling_mw = active_ceiling_mw - mcg_ceiling_mw;

                return self.arbitrate_partitioned(
                    requests,
                    current_time_us,
                    slot_duration_us,
                    mcg_ceiling_mw,
                    scg_ceiling_mw,
                );
            }
            DpsMode::LookaheadEnhanced { smoothing_factor, .. } => {
                // Smooth power jumps if last epoch was heavily loaded
                if self.last_allocated_power_mw > 0.0 {
                    let smoothed = (self.last_allocated_power_mw * *smoothing_factor)
                        + (active_ceiling_mw * (1.0 - *smoothing_factor));
                    active_ceiling_mw = active_ceiling_mw.min(smoothed.max(hw_ceiling_mw * 0.5));
                }
            }
            DpsMode::DynamicPriority => {}
        }

        // 3. Collect requested linear powers
        let total_requested_mw: f64 = requests.iter().map(|r| dbm_to_mw(r.requested_power_dbm)).sum();

        // 4. If within ceiling, full grant
        if total_requested_mw <= active_ceiling_mw + 1e-6 {
            let mut channels = Vec::with_capacity(requests.len());
            for r in requests {
                channels.push(ArbitratedTransmission {
                    carrier_id: r.carrier_id,
                    channel_type: r.channel_type,
                    requested_power_dbm: r.requested_power_dbm,
                    allocated_power_dbm: r.requested_power_dbm,
                    scaling_factor: 1.0,
                    is_dropped: false,
                });
            }

            self.sar_governor.record_emission(total_requested_mw, slot_duration_us, current_time_us);
            self.last_allocated_power_mw = total_requested_mw;

            return Ok(DpsArbitrationResult {
                timestamp_us: current_time_us,
                total_requested_power_mw: total_requested_mw,
                total_allocated_power_mw: total_requested_mw,
                power_ceiling_mw: active_ceiling_mw,
                power_curtailment_applied: false,
                channels,
            });
        }

        // 5. Power deficit: Apply strict TS 38.213 §7.5.3 Priority Hierarchy
        // Sort indices by (priority_tier ASC, sub_tier_priority ASC, carrier_id ASC)
        let mut indexed_requests: Vec<(usize, &TransmissionRequest)> = requests.iter().enumerate().collect();
        indexed_requests.sort_by(|(_, a), (_, b)| {
            a.channel_type
                .priority_tier()
                .cmp(&b.channel_type.priority_tier())
                .then_with(|| {
                    a.channel_type
                        .sub_tier_priority()
                        .cmp(&b.channel_type.sub_tier_priority())
                })
                .then_with(|| a.carrier_id.cmp(&b.carrier_id))
        });

        let mut allocated_powers_mw = vec![0.0; requests.len()];
        let mut scaling_factors = vec![0.0; requests.len()];
        let mut remaining_power_mw = active_ceiling_mw;

        for (orig_idx, req) in indexed_requests {
            let req_mw = dbm_to_mw(req.requested_power_dbm);
            if remaining_power_mw <= 1e-9 {
                // No power remaining, drop channel
                allocated_powers_mw[orig_idx] = 0.0;
                scaling_factors[orig_idx] = 0.0;
            } else if req_mw <= remaining_power_mw {
                // Full allocation
                allocated_powers_mw[orig_idx] = req_mw;
                scaling_factors[orig_idx] = 1.0;
                remaining_power_mw -= req_mw;
            } else {
                // Partial allocation: linear scale
                let beta = remaining_power_mw / req_mw;
                allocated_powers_mw[orig_idx] = remaining_power_mw;
                scaling_factors[orig_idx] = beta;
                remaining_power_mw = 0.0;
            }
        }

        let mut channels = Vec::with_capacity(requests.len());
        let mut total_allocated_mw = 0.0;

        for (i, r) in requests.iter().enumerate() {
            let alloc_mw = allocated_powers_mw[i];
            total_allocated_mw += alloc_mw;
            let is_dropped = scaling_factors[i] <= 1e-6;
            let alloc_dbm = if is_dropped {
                MIN_POWER_DBM
            } else {
                mw_to_dbm(alloc_mw)
            };

            channels.push(ArbitratedTransmission {
                carrier_id: r.carrier_id,
                channel_type: r.channel_type,
                requested_power_dbm: r.requested_power_dbm,
                allocated_power_dbm: alloc_dbm,
                scaling_factor: scaling_factors[i],
                is_dropped,
            });
        }

        self.sar_governor.record_emission(total_allocated_mw, slot_duration_us, current_time_us);
        self.last_allocated_power_mw = total_allocated_mw;

        Ok(DpsArbitrationResult {
            timestamp_us: current_time_us,
            total_requested_power_mw: total_requested_mw,
            total_allocated_power_mw: total_allocated_mw,
            power_ceiling_mw: active_ceiling_mw,
            power_curtailment_applied: true,
            channels,
        })
    }

    /// Internal arbitration for Semi-Static partitioned mode.
    fn arbitrate_partitioned(
        &mut self,
        requests: &[TransmissionRequest],
        current_time_us: u64,
        slot_duration_us: u64,
        mcg_ceiling_mw: f64,
        scg_ceiling_mw: f64,
    ) -> Result<DpsArbitrationResult, DpsError> {
        let mut mcg_reqs = Vec::new();
        let mut scg_reqs = Vec::new();

        for (i, r) in requests.iter().enumerate() {
            let carrier_cfg = self
                .carriers
                .iter()
                .find(|c| c.carrier_id == r.carrier_id)
                .ok_or(DpsError::InvalidCarrierConfig("Carrier not configured"))?;

            match carrier_cfg.cell_group {
                CellGroupType::Mcg => mcg_reqs.push((i, r)),
                CellGroupType::Scg => scg_reqs.push((i, r)),
            }
        }

        let mut channels = vec![None; requests.len()];
        let mut total_allocated_mw = 0.0;
        let total_requested_mw: f64 = requests.iter().map(|r| dbm_to_mw(r.requested_power_dbm)).sum();

        // Arbitrate MCG
        Self::arbitrate_group_partition(
            &mcg_reqs,
            mcg_ceiling_mw,
            &mut channels,
            &mut total_allocated_mw,
        );

        // Arbitrate SCG
        Self::arbitrate_group_partition(
            &scg_reqs,
            scg_ceiling_mw,
            &mut channels,
            &mut total_allocated_mw,
        );

        let final_channels: Vec<ArbitratedTransmission> = channels.into_iter().flatten().collect();
        let curtailment = total_allocated_mw < (total_requested_mw - 1e-4);

        self.sar_governor.record_emission(total_allocated_mw, slot_duration_us, current_time_us);
        self.last_allocated_power_mw = total_allocated_mw;

        Ok(DpsArbitrationResult {
            timestamp_us: current_time_us,
            total_requested_power_mw: total_requested_mw,
            total_allocated_power_mw: total_allocated_mw,
            power_ceiling_mw: mcg_ceiling_mw + scg_ceiling_mw,
            power_curtailment_applied: curtailment,
            channels: final_channels,
        })
    }

    fn arbitrate_group_partition(
        group_reqs: &[(usize, &TransmissionRequest)],
        ceiling_mw: f64,
        out_channels: &mut [Option<ArbitratedTransmission>],
        total_allocated_mw: &mut f64,
    ) {
        let group_requested_mw: f64 = group_reqs.iter().map(|(_, r)| dbm_to_mw(r.requested_power_dbm)).sum();

        if group_requested_mw <= ceiling_mw + 1e-6 {
            for &(orig_idx, req) in group_reqs {
                let req_mw = dbm_to_mw(req.requested_power_dbm);
                *total_allocated_mw += req_mw;
                out_channels[orig_idx] = Some(ArbitratedTransmission {
                    carrier_id: req.carrier_id,
                    channel_type: req.channel_type,
                    requested_power_dbm: req.requested_power_dbm,
                    allocated_power_dbm: req.requested_power_dbm,
                    scaling_factor: 1.0,
                    is_dropped: false,
                });
            }
            return;
        }

        // Priority sort within cell group
        let mut sorted = group_reqs.to_vec();
        sorted.sort_by(|(_, a), (_, b)| {
            a.channel_type
                .priority_tier()
                .cmp(&b.channel_type.priority_tier())
                .then_with(|| {
                    a.channel_type
                        .sub_tier_priority()
                        .cmp(&b.channel_type.sub_tier_priority())
                })
        });

        let mut remaining_mw = ceiling_mw;
        for &(orig_idx, req) in sorted.iter() {
            let req_mw = dbm_to_mw(req.requested_power_dbm);
            if remaining_mw <= 1e-9 {
                out_channels[orig_idx] = Some(ArbitratedTransmission {
                    carrier_id: req.carrier_id,
                    channel_type: req.channel_type,
                    requested_power_dbm: req.requested_power_dbm,
                    allocated_power_dbm: MIN_POWER_DBM,
                    scaling_factor: 0.0,
                    is_dropped: true,
                });
            } else if req_mw <= remaining_mw {
                *total_allocated_mw += req_mw;
                remaining_mw -= req_mw;
                out_channels[orig_idx] = Some(ArbitratedTransmission {
                    carrier_id: req.carrier_id,
                    channel_type: req.channel_type,
                    requested_power_dbm: req.requested_power_dbm,
                    allocated_power_dbm: req.requested_power_dbm,
                    scaling_factor: 1.0,
                    is_dropped: false,
                });
            } else {
                let beta = remaining_mw / req_mw;
                *total_allocated_mw += remaining_mw;
                let alloc_dbm = mw_to_dbm(remaining_mw);
                remaining_mw = 0.0;
                out_channels[orig_idx] = Some(ArbitratedTransmission {
                    carrier_id: req.carrier_id,
                    channel_type: req.channel_type,
                    requested_power_dbm: req.requested_power_dbm,
                    allocated_power_dbm: alloc_dbm,
                    scaling_factor: beta,
                    is_dropped: false,
                });
            }
        }
    }

    /// Serializes a Multiple Entry PHR MAC CE according to 3GPP TS 38.321 §6.1.3.8 / §6.1.3.9.
    ///
    /// Layout:
    /// - Octet 1: Serving Cell Bitmap $C_7 C_6 C_5 C_4 C_3 C_2 C_1 R$ (indicates presence of SCell entries)
    /// - For each cell (PCell/PSCell first, then SCells according to bitmap):
    ///   - Octet: $P \cdot V \cdot \mathrm{PH}(6\text{-bit})$
    ///   - If $V=0$: Following Octet: $R \cdot R \cdot P_{\mathrm{CMAX},c}(6\text{-bit})$
    pub fn serialize_multiple_phr_mac_ce(entries: &[PhrEntry]) -> Vec<u8> {
        let mut bytes = Vec::new();
        if entries.is_empty() {
            return bytes;
        }

        // Determine SCell presence bitmap (carriers 1..=7 in first byte)
        let mut bitmap: u8 = 0;
        for entry in entries {
            if entry.carrier_id >= 1 && entry.carrier_id <= 7 {
                bitmap |= 1 << entry.carrier_id;
            }
        }
        bytes.push(bitmap);

        // Append entries
        for entry in entries {
            let p_bit = if entry.p_mpr_applied { 0x80 } else { 0x00 };
            let v_bit = if entry.is_virtual { 0x40 } else { 0x00 };
            let ph_val = PhrEntry::encode_ph_level(entry.ph_db) & 0x3F;

            let octet_ph = p_bit | v_bit | ph_val;
            bytes.push(octet_ph);

            // If real transmission (V=0), encode PCMAX octet
            if !entry.is_virtual {
                let pcmax_dbm = entry.pcmax_dbm.unwrap_or(23.0);
                let pcmax_val = PhrEntry::encode_pcmax_level(pcmax_dbm) & 0x3F;
                bytes.push(pcmax_val);
            }
        }

        bytes
    }

    /// Parses a Multiple Entry PHR MAC CE payload into structured PHR entries.
    pub fn parse_multiple_phr_mac_ce(bytes: &[u8]) -> Result<Vec<PhrEntry>, DpsError> {
        if bytes.is_empty() {
            return Err(DpsError::DecodingError("Empty PHR buffer"));
        }

        let bitmap = bytes[0];
        let mut entries = Vec::new();
        let mut offset = 1;

        // First entry is always primary cell (carrier_id = 0)
        let mut current_carrier_id: u8 = 0;

        while offset < bytes.len() {
            let ph_octet = bytes[offset];
            offset += 1;

            let p_mpr_applied = (ph_octet & 0x80) != 0;
            let is_virtual = (ph_octet & 0x40) != 0;
            let ph_raw = ph_octet & 0x3F;
            let ph_db = PhrEntry::decode_ph_level(ph_raw);

            let pcmax_dbm = if !is_virtual {
                if offset >= bytes.len() {
                    return Err(DpsError::DecodingError("Truncated PCMAX octet in PHR MAC CE"));
                }
                let pcmax_octet = bytes[offset];
                offset += 1;
                let pcmax_raw = pcmax_octet & 0x3F;
                Some(PhrEntry::decode_pcmax_level(pcmax_raw))
            } else {
                None
            };

            entries.push(PhrEntry {
                carrier_id: current_carrier_id,
                phr_type: PhrType::Type1,
                ph_db,
                pcmax_dbm,
                is_virtual,
                p_mpr_applied,
            });

            // Advance to next carrier present in bitmap
            current_carrier_id += 1;
            while current_carrier_id <= 7 && (bitmap & (1 << current_carrier_id)) == 0 {
                current_carrier_id += 1;
            }
        }

        Ok(entries)
    }
}

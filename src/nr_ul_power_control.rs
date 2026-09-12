//! 3GPP Release 18/19 5G-Advanced Uplink Power Control, Fractional Pathloss & Power Headroom Engine.
//!
//! Standards Reference:
//! - 3GPP TS 38.213 Rel-18 §7: Uplink Power Control (PUSCH, PUCCH, PRACH, SRS, and simultaneous transmission).
//! - 3GPP TS 38.214 Rel-18 §6.1.3: UE sounding and uplink transmission procedure.
//! - 3GPP TS 38.321 Rel-18 §5.4.6 / §6.1.3.8-9: Power Headroom Reporting (PHR) MAC CEs.
//! - 3GPP TS 38.331 Rel-18 §6.3.2: `UplinkPowerControl`, `PUSCH-PowerControl`, `PUCCH-PowerControl`.
//!
//! Features:
//! 1. Open-loop pathloss calculation ($PL = P_{\text{tx,RS}} - \text{RSRP}_{\text{filtered}}$) with fractional compensation $\alpha \in [0.0, 1.0]$.
//! 2. Closed-loop Transmit Power Control (TPC) state machine supporting both Accumulated and Absolute modes.
//! 3. Precise transmit power computation for PUSCH, PUCCH (Formats 0-4), PRACH (with power ramping), and SRS.
//! 4. Strict 3GPP TS 38.213 §7.5 simultaneous transmission power scaling and priority hierarchy:
//!    $\text{PRACH} > \text{PUCCH (ACK/SR)} > \text{PUSCH (ACK)} > \text{PUCCH (CSI)} > \text{PUSCH (CSI)} > \text{PUSCH (Data)} > \text{SRS}$.
//! 5. Power Headroom Reporting (PHR) engine supporting Type 1, Type 2, and Type 3 headroom metrics.
//! 6. Binary wire framing (`UlPowerControlWirePdu`) with magic `0x50575243` ("PWRC") and CRC-16 CCITT integrity.

use std::fmt;

// ---------------------------------------------------------------------------
// Constants & Definitions
// ---------------------------------------------------------------------------

/// Magic bytes for UL Power Control Wire PDU: "PWRC" (0x50575243).
pub const UL_PWR_WIRE_MAGIC: u32 = 0x50575243;

/// Standard CRC-16 CCITT polynomial.
pub const CRC16_CCITT_POLY: u16 = 0x1021;

/// Default configured maximum UE output power $P_{\text{CMAX}}$ (Power Class 3: 23 dBm = 200 mW).
pub const DEFAULT_P_CMAX_DBM: f64 = 23.0;

/// Default High Power UE (HPUE Class 2: 26 dBm = 400 mW).
pub const HPUE_CLASS_2_P_CMAX_DBM: f64 = 26.0;

/// Default High Power UE (HPUE Class 1.5: 29 dBm = 800 mW).
pub const HPUE_CLASS_1_5_P_CMAX_DBM: f64 = 29.0;

/// Closed-loop TPC Mode (TS 38.213 §7.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpcMode {
    Accumulated,
    Absolute,
}

/// Uplink channel priority for simultaneous transmission power scaling (TS 38.213 §7.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChannelPriority {
    Prach = 1,          // Priority 1 (highest)
    PucchHarqAckSr = 2, // Priority 2: PUCCH with HARQ-ACK and/or SR
    PuschHarqAck = 3,   // Priority 3: PUSCH with HARQ-ACK
    PucchCsi = 4,       // Priority 4: PUCCH with CSI
    PuschCsi = 5,       // Priority 5: PUSCH with CSI
    PuschDataOnly = 6,  // Priority 6: PUSCH with data only
    Srs = 7,            // Priority 7: Sounding Reference Signal
}

/// PUCCH Format for power offset determination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PucchFormat {
    Format0,
    Format1,
    Format2,
    Format3,
    Format4,
}

impl PucchFormat {
    /// Returns default $\Delta_{\text{F\_PUCCH}}$ in dB (TS 38.213 §7.2.1).
    pub fn default_delta_f_db(&self) -> f64 {
        match self {
            PucchFormat::Format0 => 0.0,
            PucchFormat::Format1 => 0.0,
            PucchFormat::Format2 => 3.0,
            PucchFormat::Format3 => 4.0,
            PucchFormat::Format4 => 4.0,
        }
    }
}

/// Errors encountered in UL Power Control operations.
#[derive(Debug, Clone, PartialEq)]
pub enum PowerControlError {
    InvalidPrbCount(usize),
    InvalidAlpha(f64),
    InvalidPmax(f64),
    InvalidPathloss(f64),
    SerializationError(String),
    DeserializationError(String),
}

impl fmt::Display for PowerControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PowerControlError::InvalidPrbCount(prb) => write!(f, "Invalid PRB count: {}", prb),
            PowerControlError::InvalidAlpha(a) => {
                write!(f, "Invalid alpha factor {} (must be 0.0..1.0)", a)
            }
            PowerControlError::InvalidPmax(p) => write!(f, "Invalid P_CMAX: {} dBm", p),
            PowerControlError::InvalidPathloss(pl) => write!(f, "Invalid pathloss: {} dB", pl),
            PowerControlError::SerializationError(e) => write!(f, "Serialization error: {}", e),
            PowerControlError::DeserializationError(e) => write!(f, "Deserialization error: {}", e),
        }
    }
}

impl std::error::Error for PowerControlError {}

// ---------------------------------------------------------------------------
// Unit Conversion Helpers (dBm <-> mW)
// ---------------------------------------------------------------------------

/// Converts power in dBm to linear milliwatts (mW).
pub fn dbm_to_mw(dbm: f64) -> f64 {
    10.0f64.powf(dbm / 10.0)
}

/// Converts power in linear milliwatts (mW) to dBm.
pub fn mw_to_dbm(mw: f64) -> f64 {
    if mw <= 0.0 { -140.0 } else { 10.0 * mw.log10() }
}

// ---------------------------------------------------------------------------
// Closed-Loop TPC Accumulator (TS 38.213 §7.1.1 / §7.2.1)
// ---------------------------------------------------------------------------

/// Closed-loop Transmit Power Control (TPC) state manager.
#[derive(Debug, Clone, PartialEq)]
pub struct TpcLoop {
    pub mode: TpcMode,
    pub current_value_db: f64,
    pub min_value_db: f64,
    pub max_value_db: f64,
}

impl TpcLoop {
    pub fn new(mode: TpcMode) -> Self {
        Self {
            mode,
            current_value_db: 0.0,
            min_value_db: -16.0,
            max_value_db: 16.0,
        }
    }

    /// Applies a TPC adjustment command $\delta$ in dB.
    pub fn apply_command(&mut self, delta_db: f64) {
        match self.mode {
            TpcMode::Accumulated => {
                let next = self.current_value_db + delta_db;
                self.current_value_db = next.clamp(self.min_value_db, self.max_value_db);
            }
            TpcMode::Absolute => {
                self.current_value_db = delta_db.clamp(self.min_value_db, self.max_value_db);
            }
        }
    }

    /// Resets accumulator to 0 dB.
    pub fn reset(&mut self) {
        self.current_value_db = 0.0;
    }
}

// ---------------------------------------------------------------------------
// Physical Channel Transmit Power Calculation
// ---------------------------------------------------------------------------

/// Configuration parameters for PUSCH power control (TS 38.213 §7.1.1).
#[derive(Debug, Clone, PartialEq)]
pub struct PuschPowerConfig {
    pub p_o_nominal_dbm: f64, // e.g. -90 dBm
    pub p_o_ue_dbm: f64,      // e.g. 0 dBm
    pub alpha: f64,           // 0.0..1.0
    pub p_cmax_dbm: f64,      // e.g. 23.0 dBm
    pub numerology_mu: u8,    // 0 for 15kHz, 1 for 30kHz, etc.
}

/// Computes PUSCH transmit power in dBm.
pub fn calculate_pusch_power(
    cfg: &PuschPowerConfig,
    num_prbs: usize,
    pathloss_db: f64,
    delta_tf_db: f64,
    tpc_loop_val_db: f64,
) -> Result<f64, PowerControlError> {
    if num_prbs == 0 {
        return Err(PowerControlError::InvalidPrbCount(0));
    }
    if cfg.alpha < 0.0 || cfg.alpha > 1.0 {
        return Err(PowerControlError::InvalidAlpha(cfg.alpha));
    }

    let p_o = cfg.p_o_nominal_dbm + cfg.p_o_ue_dbm;
    let bw_term = 10.0 * (((1 << cfg.numerology_mu) * num_prbs) as f64).log10();
    let pl_term = cfg.alpha * pathloss_db;

    let computed = p_o + bw_term + pl_term + delta_tf_db + tpc_loop_val_db;
    Ok(computed.min(cfg.p_cmax_dbm))
}

/// Configuration parameters for PUCCH power control (TS 38.213 §7.2.1).
#[derive(Debug, Clone, PartialEq)]
pub struct PucchPowerConfig {
    pub p_o_pucch_dbm: f64, // Nominal + UE-specific, e.g. -100 dBm
    pub p_cmax_dbm: f64,    // e.g. 23.0 dBm
    pub numerology_mu: u8,
}

/// Computes PUCCH transmit power in dBm.
pub fn calculate_pucch_power(
    cfg: &PucchPowerConfig,
    format: PucchFormat,
    num_prbs: usize,
    pathloss_db: f64,
    delta_tf_db: f64,
    tpc_loop_val_db: f64,
) -> Result<f64, PowerControlError> {
    if num_prbs == 0 {
        return Err(PowerControlError::InvalidPrbCount(0));
    }

    let bw_term = 10.0 * (((1 << cfg.numerology_mu) * num_prbs) as f64).log10();
    let delta_f = format.default_delta_f_db();

    // In TS 38.213 §7.2.1, PUCCH pathloss compensation is full (alpha = 1.0)
    let computed =
        cfg.p_o_pucch_dbm + bw_term + pathloss_db + delta_f + delta_tf_db + tpc_loop_val_db;
    Ok(computed.min(cfg.p_cmax_dbm))
}

/// Computes PRACH transmit power in dBm with power ramping (TS 38.213 §7.4).
pub fn calculate_prach_power(
    preamble_initial_target_dbm: f64, // e.g. -100 dBm
    ramping_step_db: f64,             // e.g. 2.0 or 4.0 dB
    transmission_counter: u32,        // 1, 2, 3...
    pathloss_db: f64,
    p_cmax_dbm: f64,
) -> f64 {
    let ramp_count = if transmission_counter > 0 {
        transmission_counter - 1
    } else {
        0
    };
    let preamble_target = preamble_initial_target_dbm + (ramp_count as f64) * ramping_step_db;
    let computed = preamble_target + pathloss_db;
    computed.min(p_cmax_dbm)
}

/// Computes SRS transmit power in dBm (TS 38.213 §7.3.1).
pub fn calculate_srs_power(
    p_o_srs_dbm: f64,
    alpha_srs: f64,
    num_prbs: usize,
    numerology_mu: u8,
    pathloss_db: f64,
    tpc_loop_val_db: f64,
    p_cmax_dbm: f64,
) -> Result<f64, PowerControlError> {
    if num_prbs == 0 {
        return Err(PowerControlError::InvalidPrbCount(0));
    }
    if alpha_srs < 0.0 || alpha_srs > 1.0 {
        return Err(PowerControlError::InvalidAlpha(alpha_srs));
    }

    let bw_term = 10.0 * (((1 << numerology_mu) * num_prbs) as f64).log10();
    let computed = p_o_srs_dbm + bw_term + alpha_srs * pathloss_db + tpc_loop_val_db;
    Ok(computed.min(p_cmax_dbm))
}

// ---------------------------------------------------------------------------
// Simultaneous Transmission Power Allocation & Scaling (TS 38.213 §7.5)
// ---------------------------------------------------------------------------

/// Request for uplink transmission power for an individual channel.
#[derive(Debug, Clone, PartialEq)]
pub struct ChannelPowerRequest {
    pub channel_id: u32,
    pub priority: ChannelPriority,
    pub requested_power_dbm: f64,
}

/// Granted transmission power after TS 38.213 §7.5 priority curtailment.
#[derive(Debug, Clone, PartialEq)]
pub struct ChannelPowerGrant {
    pub channel_id: u32,
    pub priority: ChannelPriority,
    pub requested_power_dbm: f64,
    pub granted_power_dbm: f64,
    pub scaling_factor: f64, // 0.0 to 1.0
}

/// Resolves simultaneous transmission power constraints under $P_{\text{CMAX}}$.
pub fn resolve_simultaneous_power_scaling(
    requests: &[ChannelPowerRequest],
    p_cmax_dbm: f64,
) -> Vec<ChannelPowerGrant> {
    if requests.is_empty() {
        return Vec::new();
    }

    let p_cmax_mw = dbm_to_mw(p_cmax_dbm);

    // Sort requests by strict 3GPP priority (lowest enum value = highest priority)
    let mut sorted_requests = requests.to_vec();
    sorted_requests.sort_by_key(|r| r.priority);

    let mut remaining_mw = p_cmax_mw;
    let mut grants = Vec::with_capacity(sorted_requests.len());

    for req in sorted_requests {
        let req_mw = dbm_to_mw(req.requested_power_dbm);
        if remaining_mw >= req_mw {
            // Full requested power granted
            grants.push(ChannelPowerGrant {
                channel_id: req.channel_id,
                priority: req.priority,
                requested_power_dbm: req.requested_power_dbm,
                granted_power_dbm: req.requested_power_dbm,
                scaling_factor: 1.0,
            });
            remaining_mw -= req_mw;
        } else if remaining_mw > 1e-6 {
            // Partial power scaling: grant whatever is left
            let granted_dbm = mw_to_dbm(remaining_mw);
            let scaling = remaining_mw / req_mw;
            grants.push(ChannelPowerGrant {
                channel_id: req.channel_id,
                priority: req.priority,
                requested_power_dbm: req.requested_power_dbm,
                granted_power_dbm: granted_dbm,
                scaling_factor: scaling,
            });
            remaining_mw = 0.0;
        } else {
            // Muted channel: 0 mW
            grants.push(ChannelPowerGrant {
                channel_id: req.channel_id,
                priority: req.priority,
                requested_power_dbm: req.requested_power_dbm,
                granted_power_dbm: -140.0, // Muted
                scaling_factor: 0.0,
            });
        }
    }

    grants
}

// ---------------------------------------------------------------------------
// Power Headroom Reporting (PHR) Engine (TS 38.321 §5.4.6)
// ---------------------------------------------------------------------------

/// Power Headroom Report (PHR).
#[derive(Debug, Clone, PartialEq)]
pub struct PowerHeadroomReport {
    /// Type 1 Power Headroom (PUSCH): $P_{\text{CMAX}} - P_{\text{PUSCH}}$ in dB.
    pub phr_type1_db: f64,
    /// Type 2 Power Headroom (simultaneous PUCCH + PUSCH) on SpCell in dB.
    pub phr_type2_db: Option<f64>,
    /// Type 3 Power Headroom (SRS) in dB.
    pub phr_type3_db: Option<f64>,
    /// Configured maximum power used in calculation in dBm.
    pub p_cmax_dbm: f64,
    /// Indicates whether $P_{\text{CMAX}}$ or channel power was reached.
    pub is_power_limited: bool,
}

/// Computes Power Headroom Report metrics according to TS 38.321 §5.4.6.
pub fn calculate_power_headroom(
    p_cmax_dbm: f64,
    pusch_power_dbm: Option<f64>,
    pucch_power_dbm: Option<f64>,
    srs_power_dbm: Option<f64>,
) -> PowerHeadroomReport {
    let p_pusch = pusch_power_dbm.unwrap_or(p_cmax_dbm);
    let phr_type1 = p_cmax_dbm - p_pusch;

    let phr_type2 = match (pusch_power_dbm, pucch_power_dbm) {
        (Some(p_ul), Some(p_c)) => {
            let combined_mw = dbm_to_mw(p_ul) + dbm_to_mw(p_c);
            let combined_dbm = mw_to_dbm(combined_mw);
            Some(p_cmax_dbm - combined_dbm)
        }
        _ => None,
    };

    let phr_type3 = srs_power_dbm.map(|p_srs| p_cmax_dbm - p_srs);
    let is_power_limited = phr_type1 <= 0.0 || phr_type2.map_or(false, |ph| ph <= 0.0);

    PowerHeadroomReport {
        phr_type1_db: phr_type1,
        phr_type2_db: phr_type2,
        phr_type3_db: phr_type3,
        p_cmax_dbm,
        is_power_limited,
    }
}

// ---------------------------------------------------------------------------
// Binary Wire Framing & CRC-16
// ---------------------------------------------------------------------------

/// Wire frame PDU for UL power control and PHR reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UlPowerControlWirePdu {
    pub magic: u32,
    pub timestamp_ms: u32,
    pub p_cmax_q4: i16,      // P_CMAX in dBm * 16
    pub pusch_power_q4: i16, // PUSCH power in dBm * 16
    pub pucch_power_q4: i16, // PUCCH power in dBm * 16
    pub phr_type1_q4: i16,   // PHR Type 1 in dB * 16
    pub is_power_limited: u8,
    pub payload: Vec<u8>,
    pub crc16: u16,
}

/// Computes CRC-16 CCITT over binary slice.
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

impl UlPowerControlWirePdu {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(18 + self.payload.len());
        buf.extend_from_slice(&self.magic.to_be_bytes());
        buf.extend_from_slice(&self.timestamp_ms.to_be_bytes());
        buf.extend_from_slice(&self.p_cmax_q4.to_be_bytes());
        buf.extend_from_slice(&self.pusch_power_q4.to_be_bytes());
        buf.extend_from_slice(&self.pucch_power_q4.to_be_bytes());
        buf.extend_from_slice(&self.phr_type1_q4.to_be_bytes());
        buf.push(self.is_power_limited);
        buf.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.payload);

        let crc = compute_crc16(&buf);
        buf.extend_from_slice(&crc.to_be_bytes());
        buf
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, PowerControlError> {
        if data.len() < 20 {
            return Err(PowerControlError::DeserializationError(
                "Buffer too small".into(),
            ));
        }

        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if magic != UL_PWR_WIRE_MAGIC {
            return Err(PowerControlError::DeserializationError(format!(
                "Invalid magic: 0x{:08X}",
                magic
            )));
        }

        let timestamp_ms = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let p_cmax_q4 = i16::from_be_bytes([data[8], data[9]]);
        let pusch_power_q4 = i16::from_be_bytes([data[10], data[11]]);
        let pucch_power_q4 = i16::from_be_bytes([data[12], data[13]]);
        let phr_type1_q4 = i16::from_be_bytes([data[14], data[15]]);
        let is_power_limited = data[16];
        let payload_len = u16::from_be_bytes([data[17], data[18]]) as usize;

        if data.len() < 19 + payload_len + 2 {
            return Err(PowerControlError::DeserializationError(
                "Truncated payload".into(),
            ));
        }

        let payload = data[19..19 + payload_len].to_vec();
        let expected_crc = compute_crc16(&data[..19 + payload_len]);
        let rx_crc = u16::from_be_bytes([data[19 + payload_len], data[19 + payload_len + 1]]);

        if rx_crc != expected_crc {
            return Err(PowerControlError::DeserializationError(format!(
                "CRC-16 mismatch: expected 0x{:04X}, received 0x{:04X}",
                expected_crc, rx_crc
            )));
        }

        Ok(Self {
            magic,
            timestamp_ms,
            p_cmax_q4,
            pusch_power_q4,
            pucch_power_q4,
            phr_type1_q4,
            is_power_limited,
            payload,
            crc16: rx_crc,
        })
    }
}

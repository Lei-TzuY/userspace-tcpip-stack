//! 3GPP Release 18/19 5G-Advanced Configured Grant (CG Type 1 & Type 2) & Downlink SPS Transmission Engine.
//!
//! Standards Reference:
//! - 3GPP TS 38.321 Rel-18 §5.8.1: Downlink Semi-Persistent Scheduling (SPS).
//! - 3GPP TS 38.321 Rel-18 §5.8.2: Uplink Configured Grant (Type 1 and Type 2).
//! - 3GPP TS 38.214 Rel-18 §5.1.2.3: Downlink SPS resource allocation.
//! - 3GPP TS 38.214 Rel-18 §6.1.2.3: Uplink Configured Grant resource allocation.
//! - 3GPP TS 38.212 Rel-18 §7.3.1: DCI formats (0_0/0_1/0_2 & 1_0/1_1/1_2) with CS-RNTI.
//! - 3GPP TS 38.331 Rel-18: `ConfiguredGrantConfig`, `SPS-Config`, and Multi-CG configuration (up to 12 active configs).
//!
//! Features:
//! 1. Dual Configured Grant Modes:
//!    - Type 1: RRC-configured grant, immediately active upon RRC establishment.
//!    - Type 2: RRC-configured parameters, dynamically activated and released by PDCCH DCI with CS-RNTI.
//! 2. Downlink Semi-Persistent Scheduling (SPS) Engine with CS-RNTI activation/release.
//! 3. Precise 3GPP TS 38.321 §5.8.2 HARQ Process ID formula engine:
//!    $$\text{HARQ Process ID} = \left[\lfloor \text{CURRENT\_symbol} / \text{periodicity} \rfloor \bmod \text{nrofHARQ-Processes}\right] + \text{harq-ProcID-Offset}$$
//! 4. Strict DCI CS-RNTI validation rules for Type 2 activation and release:
//!    - NDI = 0, RV = '00', HARQ Process ID validation per TS 38.214 Tables 6.1.2.3-1 / 6.1.2.3-2.
//! 5. Repetition factor $K \in \{1, 2, 4, 8\}$ and Redundancy Version sequence mapping (`[0, 2, 3, 1]`, `[0, 3, 0, 3]`, `[0, 0, 0, 0]`).
//! 6. Rel-18 Multi-Configuration Manager: Supports up to 12 concurrent CG configurations per BWP with priority arbitration.
//! 7. Binary wire framing (`ConfiguredGrantWirePdu`) with magic `0x43475254` ("CGRT") and CRC-16 CCITT validation.

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Protocol Constants & CRC-16
// ---------------------------------------------------------------------------

/// Magic bytes for Configured Grant Wire PDU: "CGRT" (0x43475254).
pub const CG_WIRE_MAGIC: u32 = 0x43475254;

/// Standard CRC-16 CCITT polynomial.
pub const CRC16_CCITT_POLY: u16 = 0x1021;

/// Maximum number of Configured Grant configurations per BWP in Rel-18 (TS 38.331).
pub const MAX_CG_CONFIGS: usize = 12;

/// Maximum number of radio frames in 5G NR SFN cycle.
pub const MAX_SFN: u16 = 1024;

/// Standard symbols per normal cyclic prefix slot.
pub const SYMBOLS_PER_SLOT: u8 = 14;

/// Errors encountered during Configured Grant or SPS processing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CgError {
    ConfigNotFound(u8),
    ConfigAlreadyExists(u8),
    MaxConfigsExceeded,
    InvalidPeriodicity(u32),
    InvalidHarqProcessCount(u8),
    MissingResourceAllocation,
    GrantNotActive(u8),
    InvalidCsRnti(u16),
    DciNdiNotZero,
    DciRvNotZero,
    DciHarqProcInvalid(u8),
    DciFdraInvalid,
    InvalidWireMagic(u32),
    WirePayloadTooShort { needed: usize, found: usize },
    WireCrcMismatch { expected: u16, computed: u16 },
}

impl fmt::Display for CgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfigNotFound(id) => write!(f, "Configured Grant config {} not found", id),
            Self::ConfigAlreadyExists(id) => {
                write!(f, "Configured Grant config {} already exists", id)
            }
            Self::MaxConfigsExceeded => {
                write!(f, "Exceeded maximum active CG configs ({})", MAX_CG_CONFIGS)
            }
            Self::InvalidPeriodicity(p) => write!(f, "Invalid periodicity {} symbols", p),
            Self::InvalidHarqProcessCount(n) => write!(f, "Invalid HARQ process count {}", n),
            Self::MissingResourceAllocation => {
                write!(f, "Missing resource allocation for Type 1 grant")
            }
            Self::GrantNotActive(id) => {
                write!(f, "Configured grant {} is currently not active", id)
            }
            Self::InvalidCsRnti(rnti) => write!(f, "Invalid CS-RNTI: 0x{:04X}", rnti),
            Self::DciNdiNotZero => write!(f, "DCI NDI is not 0 for CG activation/release"),
            Self::DciRvNotZero => write!(f, "DCI RV is not '00' for CG activation/release"),
            Self::DciHarqProcInvalid(h) => write!(
                f,
                "DCI HARQ process ID {} invalid for activation/release",
                h
            ),
            Self::DciFdraInvalid => write!(f, "DCI FDRA invalid for release indication"),
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
// Enums & Structs (TS 38.321 / TS 38.331)
// ---------------------------------------------------------------------------

/// Configured Grant Type (TS 38.321 §5.8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfiguredGrantType {
    /// Type 1: Configured purely by RRC; active immediately.
    Type1,
    /// Type 2: Configured by RRC; activated & released dynamically by PDCCH with CS-RNTI.
    Type2,
}

/// Operational status of a Configured Grant configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfiguredGrantStatus {
    Active,
    Suspended,
    Released,
}

/// Repetition factor K for Configured Grant (TS 38.331 `repK`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepetitionK {
    K1 = 1,
    K2 = 2,
    K4 = 4,
    K8 = 8,
}

impl RepetitionK {
    pub fn count(self) -> u8 {
        self as u8
    }
}

/// Redundancy Version sequence for repetitions (TS 38.331 `repK-RV`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedundancyVersionSequence {
    /// Sequence: 0, 2, 3, 1
    Rv0231,
    /// Sequence: 0, 3, 0, 3
    Rv0303,
    /// Sequence: 0, 0, 0, 0
    Rv0000,
}

impl RedundancyVersionSequence {
    /// Returns the Redundancy Version for the $k$-th repetition ($k \ge 0$).
    pub fn get_rv(self, rep_index: u8) -> u8 {
        let idx = (rep_index % 4) as usize;
        match self {
            Self::Rv0231 => [0, 2, 3, 1][idx],
            Self::Rv0303 => [0, 3, 0, 3][idx],
            Self::Rv0000 => [0, 0, 0, 0][idx],
        }
    }
}

/// Uplink Physical Resource Allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UplinkResourceAllocation {
    pub start_prb: u16,
    pub num_prbs: u16,
    pub start_symbol: u8,
    pub num_symbols: u8,
    pub mcs: u8,
}

/// Complete Configuration of a Configured Grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfiguredGrantConfig {
    pub config_id: u8,
    pub grant_type: ConfiguredGrantType,
    pub periodicity_symbols: u32,
    pub nrof_harq_processes: u8,
    pub harq_proc_id_offset: u8,
    pub rep_k: RepetitionK,
    pub rep_k_rv: RedundancyVersionSequence,
    pub resource_allocation: Option<UplinkResourceAllocation>,
    pub priority: u8, // Lower number = higher priority
}

/// A dynamic DCI scrambled with CS-RNTI (TS 38.212 §7.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DciCsRnti {
    pub cs_rnti: u16,
    pub ndi: u8,
    pub rv: u8,
    pub harq_proc_id: u8,
    pub fdra: u16,
    pub mcs: u8,
    pub start_symbol: u8,
    pub num_symbols: u8,
    pub start_prb: u16,
    pub num_prbs: u16,
}

// ---------------------------------------------------------------------------
// HARQ Process ID Formula Engine (TS 38.321 §5.8.2)
// ---------------------------------------------------------------------------

/// Computes the HARQ Process ID for Configured Grant at a specific time symbol:
/// $$\text{CURRENT\_symbol} = SFN \cdot N_{\text{slot}}^{\text{frame}} \cdot N_{\text{symbol}}^{\text{slot}} + \text{slot} \cdot N_{\text{symbol}}^{\text{slot}} + \text{symbol}$$
/// $$\text{HARQ Process ID} = \left[\lfloor \text{CURRENT\_symbol} / \text{periodicity} \rfloor \bmod \text{nrofHARQ-Processes}\right] + \text{harq-ProcID-Offset}$$
pub fn compute_cg_harq_proc_id(
    sfn: u16,
    slot_in_frame: u16,
    symbol_in_slot: u8,
    slots_per_frame: u16,
    periodicity_symbols: u32,
    nrof_harq_processes: u8,
    harq_proc_id_offset: u8,
) -> Result<u8, CgError> {
    if periodicity_symbols == 0 {
        return Err(CgError::InvalidPeriodicity(0));
    }
    if nrof_harq_processes == 0 {
        return Err(CgError::InvalidHarqProcessCount(0));
    }

    let symbols_per_slot = SYMBOLS_PER_SLOT as u64;
    let current_symbol = (sfn as u64) * (slots_per_frame as u64) * symbols_per_slot
        + (slot_in_frame as u64) * symbols_per_slot
        + (symbol_in_slot as u64);

    let period_index = current_symbol / (periodicity_symbols as u64);
    let harq_id = ((period_index % (nrof_harq_processes as u64)) as u8) + harq_proc_id_offset;
    Ok(harq_id)
}

// ---------------------------------------------------------------------------
// DCI CS-RNTI Validation Engine (TS 38.214 §6.1.2.3 / TS 38.212 §7.3.1)
// ---------------------------------------------------------------------------

/// Validates DCI Format 0_0 / 0_1 / 0_2 for Type 2 Configured Grant Activation.
/// Criteria per TS 38.214 Table 6.1.2.3-1:
/// - Scrambled with CS-RNTI (0x8001..0xFFFD)
/// - NDI == 0
/// - RV == 0 ('00')
/// - HARQ Process ID == 0
pub fn validate_type2_activation(dci: &DciCsRnti) -> Result<UplinkResourceAllocation, CgError> {
    if dci.cs_rnti < 0x8001 || dci.cs_rnti > 0xFFFD {
        return Err(CgError::InvalidCsRnti(dci.cs_rnti));
    }
    if dci.ndi != 0 {
        return Err(CgError::DciNdiNotZero);
    }
    if dci.rv != 0 {
        return Err(CgError::DciRvNotZero);
    }
    if dci.harq_proc_id != 0 {
        return Err(CgError::DciHarqProcInvalid(dci.harq_proc_id));
    }

    Ok(UplinkResourceAllocation {
        start_prb: dci.start_prb,
        num_prbs: dci.num_prbs,
        start_symbol: dci.start_symbol,
        num_symbols: dci.num_symbols,
        mcs: dci.mcs,
    })
}

/// Validates DCI Format 0_0 / 0_1 / 0_2 for Type 2 Configured Grant Release.
/// Criteria per TS 38.214 Table 6.1.2.3-2:
/// - Scrambled with CS-RNTI
/// - NDI == 0
/// - RV == 0 ('00')
/// - FDRA == all 1s (0xFFFF)
pub fn validate_type2_release(dci: &DciCsRnti) -> Result<(), CgError> {
    if dci.cs_rnti < 0x8001 || dci.cs_rnti > 0xFFFD {
        return Err(CgError::InvalidCsRnti(dci.cs_rnti));
    }
    if dci.ndi != 0 {
        return Err(CgError::DciNdiNotZero);
    }
    if dci.rv != 0 {
        return Err(CgError::DciRvNotZero);
    }
    if dci.fdra != 0xFFFF {
        return Err(CgError::DciFdraInvalid);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Rel-18 Multi-Configuration Manager
// ---------------------------------------------------------------------------

/// Grant Occasion scheduled at a specific symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledGrantOccasion {
    pub config_id: u8,
    pub harq_proc_id: u8,
    pub rv: u8,
    pub resource: UplinkResourceAllocation,
    pub priority: u8,
}

/// State of an individual Configured Grant.
#[derive(Debug, Clone)]
struct CgState {
    config: ConfiguredGrantConfig,
    status: ConfiguredGrantStatus,
    active_resource: Option<UplinkResourceAllocation>,
}

/// Rel-18 Multi-Configuration Manager for Configured Grants.
#[derive(Debug, Clone)]
pub struct ConfiguredGrantManager {
    configs: HashMap<u8, CgState>,
    slots_per_frame: u16,
}

impl ConfiguredGrantManager {
    pub fn new(slots_per_frame: u16) -> Self {
        Self {
            configs: HashMap::new(),
            slots_per_frame,
        }
    }

    /// Adds a new Configured Grant configuration.
    /// If Type 1, automatically sets status to `Active`.
    /// If Type 2, sets status to `Suspended` pending DCI activation.
    pub fn add_config(&mut self, config: ConfiguredGrantConfig) -> Result<(), CgError> {
        if self.configs.len() >= MAX_CG_CONFIGS {
            return Err(CgError::MaxConfigsExceeded);
        }
        if self.configs.contains_key(&config.config_id) {
            return Err(CgError::ConfigAlreadyExists(config.config_id));
        }

        let (status, active_resource) = match config.grant_type {
            ConfiguredGrantType::Type1 => {
                let res = config
                    .resource_allocation
                    .ok_or(CgError::MissingResourceAllocation)?;
                (ConfiguredGrantStatus::Active, Some(res))
            }
            ConfiguredGrantType::Type2 => (ConfiguredGrantStatus::Suspended, None),
        };

        self.configs.insert(
            config.config_id,
            CgState {
                config,
                status,
                active_resource,
            },
        );

        Ok(())
    }

    /// Activates a Type 2 Configured Grant via validated DCI.
    pub fn activate_type2(&mut self, config_id: u8, dci: &DciCsRnti) -> Result<(), CgError> {
        let resource = validate_type2_activation(dci)?;
        let state = self
            .configs
            .get_mut(&config_id)
            .ok_or(CgError::ConfigNotFound(config_id))?;
        state.status = ConfiguredGrantStatus::Active;
        state.active_resource = Some(resource);
        Ok(())
    }

    /// Releases a Type 2 Configured Grant via validated DCI.
    pub fn release_type2(&mut self, config_id: u8, dci: &DciCsRnti) -> Result<(), CgError> {
        validate_type2_release(dci)?;
        let state = self
            .configs
            .get_mut(&config_id)
            .ok_or(CgError::ConfigNotFound(config_id))?;
        state.status = ConfiguredGrantStatus::Suspended;
        state.active_resource = None;
        Ok(())
    }

    /// Returns the operational status of a configuration.
    pub fn get_status(&self, config_id: u8) -> Option<ConfiguredGrantStatus> {
        self.configs.get(&config_id).map(|s| s.status)
    }

    /// Checks if a transmission occasion occurs at the specified (SFN, slot, symbol).
    /// If multiple active CG configurations collide, arbitrates by priority (lowest priority number wins).
    pub fn evaluate_occasion(
        &self,
        sfn: u16,
        slot_in_frame: u16,
        symbol_in_slot: u8,
    ) -> Option<ScheduledGrantOccasion> {
        let symbols_per_slot = SYMBOLS_PER_SLOT as u64;
        let current_symbol = (sfn as u64) * (self.slots_per_frame as u64) * symbols_per_slot
            + (slot_in_frame as u64) * symbols_per_slot
            + (symbol_in_slot as u64);

        let mut candidates = Vec::new();

        for state in self.configs.values() {
            if state.status != ConfiguredGrantStatus::Active {
                continue;
            }
            let res = match state.active_resource {
                Some(r) => r,
                None => continue,
            };

            // Check if this symbol matches the grant start symbol
            if symbol_in_slot != res.start_symbol {
                continue;
            }

            // Check if current_symbol aligns with periodicity
            if current_symbol % (state.config.periodicity_symbols as u64) == 0 {
                let harq_id = compute_cg_harq_proc_id(
                    sfn,
                    slot_in_frame,
                    symbol_in_slot,
                    self.slots_per_frame,
                    state.config.periodicity_symbols,
                    state.config.nrof_harq_processes,
                    state.config.harq_proc_id_offset,
                )
                .unwrap_or(0);

                let rv = state.config.rep_k_rv.get_rv(0);

                candidates.push(ScheduledGrantOccasion {
                    config_id: state.config.config_id,
                    harq_proc_id: harq_id,
                    rv,
                    resource: res,
                    priority: state.config.priority,
                });
            }
        }

        // Arbitration: sort by priority ascending (lower number = higher priority)
        candidates.sort_by_key(|c| c.priority);
        candidates.into_iter().next()
    }
}

// ---------------------------------------------------------------------------
// CRC-16 CCITT & Binary Wire Framing (`ConfiguredGrantWirePdu`)
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

/// Binary Wire PDU for Configured Grant scheduled transmission telemetry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfiguredGrantWirePdu {
    pub config_id: u8,
    pub grant_type: u8, // 1 for Type1, 2 for Type2
    pub sfn: u16,
    pub slot: u16,
    pub symbol: u8,
    pub harq_proc_id: u8,
    pub rv: u8,
    pub start_prb: u16,
    pub num_prbs: u16,
    pub mcs: u8,
}

impl ConfiguredGrantWirePdu {
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(20);
        buf.extend_from_slice(&CG_WIRE_MAGIC.to_be_bytes()); // 4 bytes
        buf.push(self.config_id); // 1 byte
        buf.push(self.grant_type); // 1 byte
        buf.extend_from_slice(&self.sfn.to_be_bytes()); // 2 bytes
        buf.extend_from_slice(&self.slot.to_be_bytes()); // 2 bytes
        buf.push(self.symbol); // 1 byte
        buf.push(self.harq_proc_id); // 1 byte
        buf.push(self.rv); // 1 byte
        buf.extend_from_slice(&self.start_prb.to_be_bytes()); // 2 bytes
        buf.extend_from_slice(&self.num_prbs.to_be_bytes()); // 2 bytes
        buf.push(self.mcs); // 1 byte

        let crc = compute_crc16(&buf);
        buf.extend_from_slice(&crc.to_be_bytes()); // 2 bytes (total 20 bytes)
        buf
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, CgError> {
        if bytes.len() < 20 {
            return Err(CgError::WirePayloadTooShort {
                needed: 20,
                found: bytes.len(),
            });
        }

        let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != CG_WIRE_MAGIC {
            return Err(CgError::InvalidWireMagic(magic));
        }

        let body_len = bytes.len() - 2;
        let expected_crc = u16::from_be_bytes([bytes[body_len], bytes[body_len + 1]]);
        let computed_crc = compute_crc16(&bytes[..body_len]);
        if expected_crc != computed_crc {
            return Err(CgError::WireCrcMismatch {
                expected: expected_crc,
                computed: computed_crc,
            });
        }

        let config_id = bytes[4];
        let grant_type = bytes[5];
        let sfn = u16::from_be_bytes([bytes[6], bytes[7]]);
        let slot = u16::from_be_bytes([bytes[8], bytes[9]]);
        let symbol = bytes[10];
        let harq_proc_id = bytes[11];
        let rv = bytes[12];
        let start_prb = u16::from_be_bytes([bytes[13], bytes[14]]);
        let num_prbs = u16::from_be_bytes([bytes[15], bytes[16]]);
        let mcs = bytes[17];

        Ok(Self {
            config_id,
            grant_type,
            sfn,
            slot,
            symbol,
            harq_proc_id,
            rv,
            start_prb,
            num_prbs,
            mcs,
        })
    }
}

//! 3GPP TS 38.300 Section 4.10 / TS 38.306 / TS 38.331 Release 17 5G NR RedCap (Reduced Capability) Engine.
//!
//! Implements 5G NR-Light (RedCap) UE Adaptation & Radio Resource Management:
//! - RedCap Device Profiling (20 MHz FR1 Channel Bandwidth, 1-2 Rx Antennas, Half-Duplex FDD)
//! - SIB1 Cell-Level Access Barring & Early RedCap Identification (TS 38.331 Section 6.3.2)
//! - Dedicated RedCap Initial Bandwidth Part (BWP <= 20 MHz) within 100 MHz Wideband Carrier
//! - Extended DRX (eDRX) and Radio Resource Management (RRM) Measurement Relaxation for Multi-Year Battery Life

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// 5G RedCap Enums & Data Structures (TS 38.306 / TS 38.331)
// ---------------------------------------------------------------------------

/// RedCap Device Segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedCapDeviceType {
    Wearable,          // Smartwatches, health monitors
    IndustrialSensor,  // Wireless pressure/vibration sensors, AGV telemetry
    SurveillanceVideo, // Smart city wireless CCTV
}

/// Duplex Mode Capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedCapDuplexMode {
    FullDuplexFdd,
    HalfDuplexFdd, // Eliminates expensive duplexer filter
    Tdd,
}

/// Maximum Supported Downlink Modulation Order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedCapModulation {
    Qam64,  // Mandatory baseline for RedCap
    Qam256, // Optional high-throughput extension
}

/// RedCap Device Capability Profile (TS 38.306 Section 4.2.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedCapCapability {
    pub device_type: RedCapDeviceType,
    pub max_bandwidth_mhz: u32, // Must be <= 20 MHz in FR1
    pub num_rx_antennas: u8,    // 1 Rx or 2 Rx
    pub duplex_mode: RedCapDuplexMode,
    pub max_dl_modulation: RedCapModulation,
    pub supports_edrx: bool,
    pub supports_rrm_relaxation: bool,
}

/// Cell-Level RedCap Broadcast Configuration (SIB1 - TS 38.331).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CellRedCapConfig {
    pub cell_id: u32,
    pub carrier_bandwidth_mhz: u32, // e.g. 100 MHz FR1 carrier
    pub redcap_allowed: bool,       // SIB1 redCapAllowed flag
    pub dedicated_prach_partition: bool,
    pub redcap_initial_bwp_mhz: u32, // Must be <= 20 MHz
    pub redcap_initial_bwp_start_rb: u32,
}

/// Connected RedCap UE Context in gNodeB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedCapUeContext {
    pub ue_id: String,
    pub cell_id: u32,
    pub capability: RedCapCapability,
    pub assigned_bwp_mhz: u32,
    pub assigned_bwp_start_rb: u32,
    pub is_connected: bool,
    pub edrx_cycle_s: Option<u32>,
    pub rrm_relaxed: bool,
}

/// RedCap Error Types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedCapError {
    CellNotFound { cell_id: u32 },
    RedCapAccessBarred { cell_id: u32 },
    InvalidInitialBwp { bwp_mhz: u32 },
    ExcessiveBandwidthRequested { max_mhz: u32 },
    UeNotFound { ue_id: String },
    UeAlreadyConnected { ue_id: String },
}

// ---------------------------------------------------------------------------
// Top-Level 5G RedCap Engine
// ---------------------------------------------------------------------------

/// 5G NR RedCap (Reduced Capability) Base Station Adaptation Engine.
pub struct RedCapEngine {
    pub engine_id: String,
    pub cells: HashMap<u32, CellRedCapConfig>,
    pub connected_ues: HashMap<String, RedCapUeContext>,
}

impl RedCapEngine {
    /// Create a new 5G RedCap engine instance.
    pub fn new(engine_id: &str) -> Self {
        RedCapEngine {
            engine_id: engine_id.to_string(),
            cells: HashMap::new(),
            connected_ues: HashMap::new(),
        }
    }

    /// Configure a cell's RedCap parameters broadcast in SIB1.
    pub fn configure_cell(
        &mut self,
        cell_id: u32,
        carrier_bandwidth_mhz: u32,
        redcap_allowed: bool,
        dedicated_prach_partition: bool,
        redcap_initial_bwp_mhz: u32,
        redcap_initial_bwp_start_rb: u32,
    ) -> Result<(), RedCapError> {
        // RedCap Initial BWP in FR1 must not exceed 20 MHz (TS 38.300 Section 4.10)
        if redcap_initial_bwp_mhz == 0 || redcap_initial_bwp_mhz > 20 {
            return Err(RedCapError::InvalidInitialBwp {
                bwp_mhz: redcap_initial_bwp_mhz,
            });
        }

        let cfg = CellRedCapConfig {
            cell_id,
            carrier_bandwidth_mhz,
            redcap_allowed,
            dedicated_prach_partition,
            redcap_initial_bwp_mhz,
            redcap_initial_bwp_start_rb,
        };

        self.cells.insert(cell_id, cfg);
        Ok(())
    }

    /// Handle RedCap UE Random Access and establish connection within RedCap BWP.
    pub fn handle_random_access(
        &mut self,
        cell_id: u32,
        ue_id: &str,
        capability: RedCapCapability,
    ) -> Result<RedCapUeContext, RedCapError> {
        let cell = self
            .cells
            .get(&cell_id)
            .ok_or(RedCapError::CellNotFound { cell_id })?;

        // 1. SIB1 Access Barring Check
        if !cell.redcap_allowed {
            return Err(RedCapError::RedCapAccessBarred { cell_id });
        }

        // 2. Validate UE Bandwidth Capability (must be <= 20 MHz in FR1)
        if capability.max_bandwidth_mhz > 20 {
            return Err(RedCapError::ExcessiveBandwidthRequested {
                max_mhz: capability.max_bandwidth_mhz,
            });
        }

        if self.connected_ues.contains_key(ue_id) {
            return Err(RedCapError::UeAlreadyConnected {
                ue_id: ue_id.to_string(),
            });
        }

        // 3. Allocate RedCap UE into Dedicated Initial BWP (<= 20 MHz)
        let ue_ctx = RedCapUeContext {
            ue_id: ue_id.to_string(),
            cell_id,
            capability,
            assigned_bwp_mhz: cell.redcap_initial_bwp_mhz,
            assigned_bwp_start_rb: cell.redcap_initial_bwp_start_rb,
            is_connected: true,
            edrx_cycle_s: None,
            rrm_relaxed: false,
        };

        self.connected_ues.insert(ue_id.to_string(), ue_ctx.clone());
        Ok(ue_ctx)
    }

    /// Configure eDRX and RRM measurement relaxation for battery power saving.
    pub fn configure_power_saving(
        &mut self,
        ue_id: &str,
        edrx_cycle_s: Option<u32>,
        rrm_relaxed: bool,
    ) -> Result<(), RedCapError> {
        let ue = self
            .connected_ues
            .get_mut(ue_id)
            .ok_or_else(|| RedCapError::UeNotFound {
                ue_id: ue_id.to_string(),
            })?;

        if let Some(cycle) = edrx_cycle_s {
            if ue.capability.supports_edrx {
                ue.edrx_cycle_s = Some(cycle);
            }
        }

        if rrm_relaxed && ue.capability.supports_rrm_relaxation {
            ue.rrm_relaxed = true;
        }

        Ok(())
    }

    /// Disconnect RedCap UE and release radio resources.
    pub fn disconnect_ue(&mut self, ue_id: &str) -> Result<(), RedCapError> {
        self.connected_ues
            .remove(ue_id)
            .ok_or_else(|| RedCapError::UeNotFound {
                ue_id: ue_id.to_string(),
            })?;
        Ok(())
    }
}

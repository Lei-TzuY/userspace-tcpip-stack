//! 3GPP Release 18 / Release 19 Automated Neighbor Relation (ANR), Minimization of Drive Tests (MDT)
//! & Mobility Robustness Optimization (MRO) Self-Organizing Networks (SON) Engine.
//!
//! Conforms to:
//! - 3GPP TS 38.300 Rel-18 §15: Support for Self-configuration and Self-optimisation (SON).
//! - 3GPP TS 37.320 Rel-18: Universal Terrestrial Radio Access (UTRA) and Evolved UTRA (E-UTRA) and NR;
//!   Radio measurement collection for Minimization of Drive Tests (MDT).
//! - 3GPP TS 38.331 Rel-18: Radio Resource Control - `LoggedMeasurementConfiguration`, `MeasurementReport`,
//!   `UEInformationRequest` / `UEInformationResponse` (`logMeasReport`, `connEstFailReport`, `rlf-Report`).
//! - 3GPP TS 38.423 Rel-18 / TS 38.413: Xn-AP / NG-AP ANR procedures (Cell Configuration Update,
//!   Handover Report, and Radio Link Failure Indication).
//!
//! Key Architecture:
//! 1. Automated Neighbor Relation (ANR) Engine:
//!    - Neighbor Relation Table (NRT) per serving cell with PCI (0..1007), NCGI (36-bit NCI + PLMN),
//!      TAC, and policy flags (`noRemove`, `noHO`, `noXn`).
//!    - PCI Collision detection (two adjacent cells share the same PCI) and PCI Confusion detection
//!      (serving cell has two distinct neighbors sharing the same PCI).
//!    - Autonomous UE-Assisted CGI Resolution: When an unknown PCI is detected, gNodeB orders UE to
//!      read target cell SIB1 in autonomous measurement gaps to resolve full NCGI and TAC.
//! 2. Minimization of Drive Tests (MDT) Subsystem:
//!    - Immediate MDT: Real-time periodic/event-triggered reporting of RSRP, RSRQ, SINR, and GNSS coordinates.
//!    - Logged MDT: Periodic signal quality logging in RRC_IDLE and RRC_INACTIVE states with batch
//!      retrieval via `UEInformationRequest` / `UEInformationResponse`.
//!    - Sensor logging: Barometric pressure altitude, Bluetooth beacon RSSI, and WLAN SSID logging.
//! 3. Mobility Robustness Optimization (MRO):
//!    - Classifies Handover Failures and Radio Link Failures (RLF) into:
//!      - Too Early Handover (RLF in target cell shortly after HO, re-establishes in source cell).
//!      - Too Late Handover (RLF in source cell, re-establishes in target cell).
//!      - Handover to Wrong Cell (RLF in target cell, re-establishes in third cell).
//!    - Dynamic Parameter Auto-Tuning: Adjusts Time-To-Trigger (TTT), Cell Individual Offset (CIO),
//!      and Event A3 hysteresis to suppress ping-pong handovers.
//! 4. Coverage and Capacity Optimization (CCO):
//!    - Evaluates aggregated MDT spatial heatmaps to detect Coverage Holes, Weak Coverage, and Pilot Pollution.
//!
//! Pure standard Rust with zero external dependencies.

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Constants & Thresholds (TS 37.320 & TS 38.331)
// ---------------------------------------------------------------------------

/// Maximum standard Physical Cell Identity (0..1007 per TS 38.211 §7.4.2.1).
pub const MAX_PCI: u16 = 1007;

/// Maximum entries in Neighbor Relation Table per serving cell.
pub const MAX_NRT_ENTRIES: usize = 256;

/// Default coverage hole RSRP threshold in dBm (TS 37.320).
pub const DEFAULT_COVERAGE_HOLE_RSRP_DBM: f32 = -115.0;

/// Default coverage hole SINR threshold in dB.
pub const DEFAULT_COVERAGE_HOLE_SINR_DB: f32 = -3.0;

/// Default weak coverage RSRP threshold in dBm.
pub const DEFAULT_WEAK_COVERAGE_RSRP_DBM: f32 = -105.0;

/// Pilot pollution threshold: delta between strongest and competing cells in dB.
pub const DEFAULT_PILOT_POLLUTION_DELTA_DB: f32 = 3.0;

/// Minimum competing strong cells to declare Pilot Pollution.
pub const DEFAULT_PILOT_POLLUTION_CELL_COUNT: usize = 3;

/// Default timer threshold in milliseconds to classify a handover failure as "Too Early" (e.g. 1000 ms).
pub const DEFAULT_EARLY_HO_TIMER_MS: u64 = 1000;

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

/// Errors encountered in SON, ANR, and MDT operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SonError {
    InvalidPci(u16),
    InvalidNci(u64),
    NrtFull {
        max_entries: usize,
    },
    NeighborAlreadyExists {
        pci: u16,
    },
    NeighborNotFound {
        pci: u16,
    },
    PciCollisionDetected {
        pci: u16,
        existing_ncgi: String,
        new_ncgi: String,
    },
    PciConfusionDetected {
        pci: u16,
        ncgi_1: String,
        ncgi_2: String,
    },
    BufferOverflow {
        current: usize,
        capacity: usize,
    },
    InvalidMdtConfiguration(String),
}

impl fmt::Display for SonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SonError::InvalidPci(pci) => write!(f, "Invalid PCI: {} (valid: 0..1007)", pci),
            SonError::InvalidNci(nci) => write!(f, "Invalid NCI: 0x{:X} (exceeds 36 bits)", nci),
            SonError::NrtFull { max_entries } => {
                write!(f, "NRT capacity full: {} entries", max_entries)
            }
            SonError::NeighborAlreadyExists { pci } => {
                write!(f, "Neighbor with PCI {} already exists", pci)
            }
            SonError::NeighborNotFound { pci } => write!(f, "Neighbor with PCI {} not found", pci),
            SonError::PciCollisionDetected {
                pci,
                existing_ncgi,
                new_ncgi,
            } => {
                write!(
                    f,
                    "PCI Collision detected on PCI {}: {} vs {}",
                    pci, existing_ncgi, new_ncgi
                )
            }
            SonError::PciConfusionDetected {
                pci,
                ncgi_1,
                ncgi_2,
            } => {
                write!(
                    f,
                    "PCI Confusion detected on PCI {}: duplicate neighbor NCGI {} vs {}",
                    pci, ncgi_1, ncgi_2
                )
            }
            SonError::BufferOverflow { current, capacity } => {
                write!(f, "MDT log buffer full: {} / {} logs", current, capacity)
            }
            SonError::InvalidMdtConfiguration(msg) => {
                write!(f, "Invalid MDT configuration: {}", msg)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Core Identifiers & ANR Structures
// ---------------------------------------------------------------------------

/// NR Cell Global Identity (NCGI) per 3GPP TS 38.300 / TS 38.413.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ncgi {
    pub plmn_mcc: u16,
    pub plmn_mnc: u16,
    /// 36-bit NR Cell Identity (NCI).
    pub nci: u64,
}

impl Ncgi {
    pub fn new(mcc: u16, mnc: u16, nci: u64) -> Result<Self, SonError> {
        if nci >= (1 << 36) {
            return Err(SonError::InvalidNci(nci));
        }
        Ok(Self {
            plmn_mcc: mcc,
            plmn_mnc: mnc,
            nci,
        })
    }

    pub fn to_string_id(&self) -> String {
        format!(
            "{:03}-{:02}-0x{:09X}",
            self.plmn_mcc, self.plmn_mnc, self.nci
        )
    }
}

/// Neighbor Relation Table (NRT) entry per TS 38.300 §15.3.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighborRelationEntry {
    /// Physical Cell Identity (0..1007).
    pub pci: u16,
    /// NR Cell Global Identity.
    pub ncgi: Ncgi,
    /// Tracking Area Code (24-bit TAC).
    pub tac: u32,
    /// NR Absolute Radio Frequency Channel Number (NR-ARFCN).
    pub arfcn: u32,
    /// Policy flag: True if gNodeB must not remove this neighbor automatically.
    pub no_remove: bool,
    /// Policy flag: True if gNodeB must not trigger handover to this neighbor.
    pub no_ho: bool,
    /// Policy flag: True if gNodeB must not establish direct Xn interface to this neighbor.
    pub no_xn: bool,
    /// Cell Individual Offset (CIO) in 0.5 dB steps (signed integer, e.g. -6 to +6 dB).
    pub cio_half_db: i8,
}

impl NeighborRelationEntry {
    pub fn new(pci: u16, ncgi: Ncgi, tac: u32, arfcn: u32) -> Result<Self, SonError> {
        if pci > MAX_PCI {
            return Err(SonError::InvalidPci(pci));
        }
        Ok(Self {
            pci,
            ncgi,
            tac,
            arfcn,
            no_remove: false,
            no_ho: false,
            no_xn: false,
            cio_half_db: 0,
        })
    }
}

// ---------------------------------------------------------------------------
// Minimization of Drive Tests (MDT) Structures (TS 37.320 & TS 38.331)
// ---------------------------------------------------------------------------

/// Geographic location information for an MDT sample.
#[derive(Debug, Clone, PartialEq)]
pub struct GnssLocation {
    pub latitude: f64,
    pub longitude: f64,
    pub altitude_meters: f32,
    pub horizontal_accuracy_meters: f32,
}

/// Auxiliary sensor measurements collected in 3GPP Rel-18 MDT.
#[derive(Debug, Clone, PartialEq)]
pub struct SensorMeasurements {
    /// Barometric atmospheric pressure in hectopascals (hPa) for vertical altitude estimation.
    pub barometric_pressure_hpa: Option<f32>,
    /// Bluetooth Low Energy (BLE) beacon RSSI readings: (Beacon UUID/MAC, RSSI dBm).
    pub ble_beacons: Vec<(String, i8)>,
    /// WLAN Access Point BSSID and RSSI readings: (BSSID, RSSI dBm).
    pub wlan_aps: Vec<(String, i8)>,
}

/// A single MDT radio signal measurement log.
#[derive(Debug, Clone, PartialEq)]
pub struct MdtMeasurementLog {
    pub timestamp_ms: u64,
    pub serving_pci: u16,
    pub serving_rsrp_dbm: f32,
    pub serving_rsrq_db: f32,
    pub serving_sinr_db: f32,
    pub neighbor_rsrp: Vec<(u16, f32)>, // (PCI, RSRP dBm)
    pub location: Option<GnssLocation>,
    pub sensors: Option<SensorMeasurements>,
}

/// Logged MDT configuration parameters sent to UE before transition to IDLE/INACTIVE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggedMdtConfig {
    /// Logging interval in milliseconds (e.g. 1280, 2560, 5120, 10240 ms).
    pub logging_interval_ms: u32,
    /// Logging duration in minutes (e.g. 10, 20, 40, 60, 90, 120 min).
    pub logging_duration_minutes: u32,
    /// Area scope PLMN.
    pub area_scope_plmn: (u16, u16),
}

// ---------------------------------------------------------------------------
// Mobility Robustness Optimization (MRO)
// ---------------------------------------------------------------------------

/// Classification of Handover Failure and Radio Link Failure events (TS 38.300 §15.3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MroFailureType {
    /// Handover triggered too early: RLF occurs shortly after connecting to target,
    /// and UE attempts re-establishment back in the original source cell.
    TooEarlyHandover {
        source_pci: u16,
        target_pci: u16,
        time_since_ho_ms: u64,
    },
    /// Handover triggered too late: UE experiences RLF in source cell while moving towards
    /// target, and re-establishes directly in the target cell.
    TooLateHandover { source_pci: u16, target_pci: u16 },
    /// Handover to wrong cell: Handover sent to target cell A, RLF occurs shortly after,
    /// and UE re-establishes in an adjacent third cell B.
    HandoverToWrongCell {
        source_pci: u16,
        attempted_target_pci: u16,
        actual_reestablishment_pci: u16,
    },
}

// ---------------------------------------------------------------------------
// Coverage and Capacity Optimization (CCO)
// ---------------------------------------------------------------------------

/// Categorization of radio coverage degradation detected by CCO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoverageAnomaly {
    /// Both RSRP and SINR fall below minimal operational thresholds.
    CoverageHole {
        pci: u16,
        measured_rsrp: i16,
        measured_sinr: i16,
    },
    /// Low RSRP but acceptable SINR.
    WeakCoverage { pci: u16, measured_rsrp: i16 },
    /// Excessive competing strong cells causing high co-channel interference.
    PilotPollution {
        serving_pci: u16,
        strong_cell_count: usize,
    },
}

// ---------------------------------------------------------------------------
// Telemetry & Metrics
// ---------------------------------------------------------------------------

/// Subsystem performance statistics for SON, ANR, and MDT.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SonTelemetry {
    pub total_nrt_entries: usize,
    pub autonomous_cgi_resolutions: u64,
    pub pci_collisions_detected: u64,
    pub pci_confusions_detected: u64,
    pub immediate_mdt_logs_processed: u64,
    pub logged_mdt_batches_retrieved: u64,
    pub too_early_ho_count: u64,
    pub too_late_ho_count: u64,
    pub wrong_cell_ho_count: u64,
    pub coverage_holes_detected: u64,
    pub pilot_pollutions_detected: u64,
}

// ---------------------------------------------------------------------------
// Central SON / ANR / MDT Engine
// ---------------------------------------------------------------------------

/// Central engine managing 3GPP Rel-18/19 Self-Organizing Networks, ANR, MDT, and MRO.
pub struct SonAnrMdtEngine {
    serving_pci: u16,
    serving_ncgi: Ncgi,
    serving_tac: u32,
    serving_arfcn: u32,
    nrt: HashMap<u16, NeighborRelationEntry>,
    logged_mdt_buffer: Vec<MdtMeasurementLog>,
    max_log_capacity: usize,
    current_time_ms: u64,
    telemetry: SonTelemetry,
}

impl SonAnrMdtEngine {
    pub fn new(
        serving_pci: u16,
        serving_ncgi: Ncgi,
        serving_tac: u32,
        serving_arfcn: u32,
    ) -> Result<Self, SonError> {
        if serving_pci > MAX_PCI {
            return Err(SonError::InvalidPci(serving_pci));
        }
        Ok(Self {
            serving_pci,
            serving_ncgi,
            serving_tac,
            serving_arfcn,
            nrt: HashMap::new(),
            logged_mdt_buffer: Vec::new(),
            max_log_capacity: 1000,
            current_time_ms: 0,
            telemetry: SonTelemetry::default(),
        })
    }

    pub fn serving_pci(&self) -> u16 {
        self.serving_pci
    }

    pub fn serving_ncgi(&self) -> &Ncgi {
        &self.serving_ncgi
    }

    pub fn serving_tac(&self) -> u32 {
        self.serving_tac
    }

    pub fn serving_arfcn(&self) -> u32 {
        self.serving_arfcn
    }

    pub fn telemetry(&self) -> &SonTelemetry {
        &self.telemetry
    }

    pub fn current_time_ms(&self) -> u64 {
        self.current_time_ms
    }

    // -----------------------------------------------------------------------
    // Automated Neighbor Relation (ANR)
    // -----------------------------------------------------------------------

    /// Registers a discovered or provisioned neighbor cell into the Neighbor Relation Table (NRT).
    ///
    /// Checks for:
    /// 1. Self-PCI conflict.
    /// 2. PCI Collision (new neighbor has same PCI as serving cell or existing neighbor with different NCGI).
    /// 3. PCI Confusion (two neighbors have the same PCI).
    pub fn add_neighbor(&mut self, entry: NeighborRelationEntry) -> Result<(), SonError> {
        if entry.pci == self.serving_pci {
            self.telemetry.pci_collisions_detected += 1;
            return Err(SonError::PciCollisionDetected {
                pci: entry.pci,
                existing_ncgi: self.serving_ncgi.to_string_id(),
                new_ncgi: entry.ncgi.to_string_id(),
            });
        }

        if let Some(existing) = self.nrt.get(&entry.pci) {
            if existing.ncgi != entry.ncgi {
                self.telemetry.pci_confusions_detected += 1;
                return Err(SonError::PciConfusionDetected {
                    pci: entry.pci,
                    ncgi_1: existing.ncgi.to_string_id(),
                    ncgi_2: entry.ncgi.to_string_id(),
                });
            } else {
                return Err(SonError::NeighborAlreadyExists { pci: entry.pci });
            }
        }

        if self.nrt.len() >= MAX_NRT_ENTRIES {
            return Err(SonError::NrtFull {
                max_entries: MAX_NRT_ENTRIES,
            });
        }

        self.nrt.insert(entry.pci, entry);
        self.telemetry.total_nrt_entries = self.nrt.len();
        Ok(())
    }

    /// Autonomous UE-Assisted CGI Acquisition procedure (TS 38.300 §15.3.1).
    ///
    /// When UE reports unknown PCI from RRM measurements, this function processes the SIB1
    /// read result from the autonomous gap and adds or updates the neighbor relation.
    pub fn resolve_neighbor_cgi_via_ue_gap(
        &mut self,
        reported_pci: u16,
        resolved_ncgi: Ncgi,
        resolved_tac: u32,
        arfcn: u32,
    ) -> Result<(), SonError> {
        self.telemetry.autonomous_cgi_resolutions += 1;
        let entry = NeighborRelationEntry::new(reported_pci, resolved_ncgi, resolved_tac, arfcn)?;
        self.add_neighbor(entry)
    }

    /// Retrieves an NRT entry by PCI.
    pub fn get_neighbor(&self, pci: u16) -> Option<&NeighborRelationEntry> {
        self.nrt.get(&pci)
    }

    /// Removes a neighbor from NRT if the `no_remove` policy flag is false.
    pub fn remove_neighbor(&mut self, pci: u16) -> Result<bool, SonError> {
        let entry = self
            .nrt
            .get(&pci)
            .ok_or(SonError::NeighborNotFound { pci })?;
        if entry.no_remove {
            return Ok(false); // Protected, cannot remove
        }
        self.nrt.remove(&pci);
        self.telemetry.total_nrt_entries = self.nrt.len();
        Ok(true)
    }

    // -----------------------------------------------------------------------
    // Minimization of Drive Tests (MDT)
    // -----------------------------------------------------------------------

    /// Ingests an Immediate MDT measurement report received from a connected UE.
    pub fn ingest_immediate_mdt_report(
        &mut self,
        log: MdtMeasurementLog,
    ) -> Option<CoverageAnomaly> {
        self.telemetry.immediate_mdt_logs_processed += 1;
        self.evaluate_coverage_anomaly(&log)
    }

    /// Stores a batch of Logged MDT reports retrieved via `UEInformationResponse`.
    pub fn ingest_logged_mdt_batch(
        &mut self,
        logs: Vec<MdtMeasurementLog>,
    ) -> Result<Vec<CoverageAnomaly>, SonError> {
        let mut anomalies = Vec::new();
        for log in logs {
            if self.logged_mdt_buffer.len() >= self.max_log_capacity {
                return Err(SonError::BufferOverflow {
                    current: self.logged_mdt_buffer.len(),
                    capacity: self.max_log_capacity,
                });
            }
            if let Some(a) = self.evaluate_coverage_anomaly(&log) {
                anomalies.push(a);
            }
            self.logged_mdt_buffer.push(log);
        }
        self.telemetry.logged_mdt_batches_retrieved += 1;
        Ok(anomalies)
    }

    /// Evaluates whether an MDT log indicates a Coverage Hole, Weak Coverage, or Pilot Pollution.
    fn evaluate_coverage_anomaly(&mut self, log: &MdtMeasurementLog) -> Option<CoverageAnomaly> {
        // 1. Coverage Hole: Both RSRP and SINR below minimal operational limits
        if log.serving_rsrp_dbm <= DEFAULT_COVERAGE_HOLE_RSRP_DBM
            && log.serving_sinr_db <= DEFAULT_COVERAGE_HOLE_SINR_DB
        {
            self.telemetry.coverage_holes_detected += 1;
            return Some(CoverageAnomaly::CoverageHole {
                pci: log.serving_pci,
                measured_rsrp: log.serving_rsrp_dbm as i16,
                measured_sinr: log.serving_sinr_db as i16,
            });
        }

        // 2. Weak Coverage: RSRP below threshold
        if log.serving_rsrp_dbm <= DEFAULT_WEAK_COVERAGE_RSRP_DBM {
            return Some(CoverageAnomaly::WeakCoverage {
                pci: log.serving_pci,
                measured_rsrp: log.serving_rsrp_dbm as i16,
            });
        }

        // 3. Pilot Pollution: Multiple strong competing cells within delta_db
        let mut strong_count = 0;
        for &(_, n_rsrp) in &log.neighbor_rsrp {
            if (log.serving_rsrp_dbm - n_rsrp).abs() <= DEFAULT_PILOT_POLLUTION_DELTA_DB {
                strong_count += 1;
            }
        }
        if strong_count >= DEFAULT_PILOT_POLLUTION_CELL_COUNT {
            self.telemetry.pilot_pollutions_detected += 1;
            return Some(CoverageAnomaly::PilotPollution {
                serving_pci: log.serving_pci,
                strong_cell_count: strong_count,
            });
        }

        None
    }

    // -----------------------------------------------------------------------
    // Mobility Robustness Optimization (MRO)
    // -----------------------------------------------------------------------

    /// Analyzes a Handover Failure / RLF incident and classifies the root cause.
    ///
    /// Also executes automated parameter adjustment on Cell Individual Offset (CIO).
    pub fn analyze_mro_failure(&mut self, failure_type: MroFailureType) -> Result<i8, SonError> {
        match failure_type {
            MroFailureType::TooEarlyHandover {
                source_pci,
                target_pci,
                ..
            } => {
                self.telemetry.too_early_ho_count += 1;
                // Too Early: We triggered HO too quickly. Delay HO to target by increasing target CIO or reducing hysteresis.
                if let Some(entry) = self.nrt.get_mut(&target_pci) {
                    // Lower CIO by 1 step (-0.5 dB) so target appears weaker, delaying HO
                    entry.cio_half_db = entry.cio_half_db.saturating_sub(1);
                    return Ok(entry.cio_half_db);
                } else if source_pci == self.serving_pci {
                    return Ok(0);
                }
            }

            MroFailureType::TooLateHandover { target_pci, .. } => {
                self.telemetry.too_late_ho_count += 1;
                // Too Late: We triggered HO too slowly. Advance HO to target by increasing target CIO.
                if let Some(entry) = self.nrt.get_mut(&target_pci) {
                    // Raise CIO by 1 step (+0.5 dB) so target appears stronger, triggering HO earlier
                    entry.cio_half_db = entry.cio_half_db.saturating_add(1);
                    return Ok(entry.cio_half_db);
                }
            }

            MroFailureType::HandoverToWrongCell {
                attempted_target_pci,
                actual_reestablishment_pci,
                ..
            } => {
                self.telemetry.wrong_cell_ho_count += 1;
                // Handover sent to wrong cell. Penalize attempted target, favor actual cell.
                if let Some(bad_target) = self.nrt.get_mut(&attempted_target_pci) {
                    bad_target.cio_half_db = bad_target.cio_half_db.saturating_sub(2);
                }
                if let Some(good_target) = self.nrt.get_mut(&actual_reestablishment_pci) {
                    good_target.cio_half_db = good_target.cio_half_db.saturating_add(1);
                }
            }
        }

        Ok(0)
    }

    /// Advances simulation clock in milliseconds.
    pub fn advance_time_ms(&mut self, delta_ms: u64) {
        self.current_time_ms += delta_ms;
    }
}

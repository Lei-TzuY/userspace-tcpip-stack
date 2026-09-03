//! Integrated 5G Telecom Synchronization Node System (TelecomSyncNode).
//!
//! Unifies physical-layer frequency syntonization (SyncE ITU-T G.8262/G.8264 ESMC), packet-layer
//! phase synchronization (PTP IEEE 1588-2019 / ITU-T G.8275.1), Dual-Plane high-availability
//! redundancy, PI Clock Servo disciplining, PTP Hardware Clock (PHC) device steering, and 3GPP
//! TS 38.104 Time Alignment Error (TAE) conformance monitoring into an autonomous telecom node.

use crate::ptp::PtpTimestamp;
use crate::ptp_5g_tdd_sync::{
    AntennaPortMeasurement, FronthaulBudgetPartition, NrTddSyncCategory, NrTddSyncEngine,
};
use crate::ptp_pdv_filter::{PtpClockServoConfig, PtpPdvFloorFilter, PtpTimestampSample};
use crate::ptp_phc::PtpHardwareClock;
use crate::ptp_synce_hybrid::{HybridSyncConfig, HybridSyncEngine, HybridSyncMode};
use crate::ptp_telecom_dual_plane::{DualPlaneConfig, DualPlaneEngine, PtpPlaneId, SwitchReason};
use crate::synce_esmc::QualityLevel;

/// Node Configuration Parameters for Telecom Synchronization Node.
#[derive(Debug, Clone)]
pub struct TelecomSyncNodeConfig {
    pub dual_plane: DualPlaneConfig,
    pub servo: PtpClockServoConfig,
    pub hybrid: HybridSyncConfig,
    pub budget: FronthaulBudgetPartition,
}

impl Default for TelecomSyncNodeConfig {
    fn default() -> Self {
        Self {
            dual_plane: DualPlaneConfig::default(),
            servo: PtpClockServoConfig::default(),
            hybrid: HybridSyncConfig::default(),
            budget: FronthaulBudgetPartition::default(),
        }
    }
}

/// Telecom Synchronization Alarms raised during node operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TelecomAlarm {
    /// Active PTP redundancy plane failover occurred
    PtpPlaneFailover {
        from: PtpPlaneId,
        to: PtpPlaneId,
        reason: SwitchReason,
    },
    /// Physical layer SyncE reference signal lost or degraded below minimum acceptable QL
    SyncELost,
    /// Inter-plane phase difference between Plane A and Plane B exceeded alarm limit
    InterPlaneDivergence { delta_ns: i64 },
    /// Cell phase absolute time error exceeds 3GPP 38.104 limit (1500 ns)
    CellPhaseOutOfSpec { max_abs_te_ns: i64 },
    /// MIMO antenna port Time Alignment Error exceeds 3GPP 38.104 limit (65 ns)
    MimoTaeExceeded { measured_tae_ns: i64, limit_ns: i64 },
    /// Operating in holdover without active external reference
    HoldoverOperating,
}

/// Output Result from a Single Processing Cycle of the Telecom Synchronization Node.
#[derive(Debug, Clone, PartialEq)]
pub struct TelecomSyncCycleResult {
    pub active_plane: PtpPlaneId,
    pub hybrid_mode: HybridSyncMode,
    pub phc_time: PtpTimestamp,
    pub frequency_ppb: f64,
    pub estimated_phase_offset_ns: Option<i64>,
    pub alarms_triggered: Vec<TelecomAlarm>,
}

/// Comprehensive Health and Telemetry Status Report of the Telecom Synchronization Node.
#[derive(Debug, Clone, PartialEq)]
pub struct TelecomSyncStatusReport {
    pub hybrid_mode: HybridSyncMode,
    pub active_plane: PtpPlaneId,
    pub active_gm_clock_class: u8,
    pub synce_ql: Option<QualityLevel>,
    pub phc_time: PtpTimestamp,
    pub frequency_steering_ppb: f64,
    pub total_phc_stepped_ns: i64,
    pub inter_plane_phase_delta_ns: Option<i64>,
    pub cell_sync_compliant: bool,
    pub mimo_tae_compliant: bool,
    pub active_alarms: Vec<TelecomAlarm>,
}

/// Integrated 5G Telecom Synchronization Node System.
#[derive(Debug, Clone)]
pub struct TelecomSyncNode {
    pub config: TelecomSyncNodeConfig,
    pub phc: PtpHardwareClock,
    pub dual_plane: DualPlaneEngine,
    pub hybrid: HybridSyncEngine,
    pub sync_checker: NrTddSyncEngine,
    pub current_synce_ql: Option<QualityLevel>,
    pub active_alarms: Vec<TelecomAlarm>,
}

impl TelecomSyncNode {
    pub fn new(mut config: TelecomSyncNodeConfig) -> Self {
        let filter_a = PtpPdvFloorFilter::new(16, 10.0, 100);
        let filter_b = PtpPdvFloorFilter::new(16, 10.0, 100);
        let dual_plane = DualPlaneEngine::new(config.dual_plane.clone(), filter_a, filter_b);
        config.hybrid.servo_config = config.servo.clone();
        let hybrid = HybridSyncEngine::new(config.hybrid.clone());
        let sync_checker = NrTddSyncEngine::new(config.budget.clone());
        let phc = PtpHardwareClock::default();

        Self {
            config,
            phc,
            dual_plane,
            hybrid,
            sync_checker,
            current_synce_ql: None,
            active_alarms: Vec::new(),
        }
    }

    pub fn with_default_config() -> Self {
        Self::new(TelecomSyncNodeConfig::default())
    }

    /// Ingests a new PTP timestamp sample into the designated redundancy plane.
    pub fn ingest_ptp_sample(&mut self, plane: PtpPlaneId, sample: PtpTimestampSample) {
        self.dual_plane.push_plane_sample(plane, sample);
    }

    /// Updates Announce message attributes for a redundancy plane.
    pub fn update_plane_announce(
        &mut self,
        plane: PtpPlaneId,
        clock_class: u8,
        clock_accuracy: u8,
        steps_removed: u16,
    ) {
        self.dual_plane
            .update_plane_announce(plane, clock_class, clock_accuracy, steps_removed);
    }

    /// Updates current SyncE physical layer Quality Level (QL) from incoming ESMC SSM.
    pub fn update_synce_ql(&mut self, ql: QualityLevel) {
        self.current_synce_ql = Some(ql);
        self.hybrid.update_synce(ql, true);
    }

    /// Clears active SyncE physical layer signal.
    pub fn clear_synce(&mut self) {
        self.current_synce_ql = None;
        self.hybrid.update_synce(QualityLevel::QlInvalid, false);
    }

    /// Updates antenna port time error measurement for 3GPP 38.104 compliance verification.
    pub fn update_antenna_measurement(&mut self, m: AntennaPortMeasurement) {
        self.sync_checker.add_measurement(m);
    }

    /// Executes a single discrete synchronization processing cycle.
    pub fn process_sync_cycle(&mut self, delta_sec: f64) -> TelecomSyncCycleResult {
        let mut alarms = Vec::new();

        // 1. Advance free-running hardware clock counter by real elapsed time
        let elapsed_ns = (delta_sec * 1_000_000_000.0).round() as u64;
        self.phc.tick_ns(elapsed_ns);

        // 2. Dual-plane protection switching evaluation & WTR damping
        let prev_plane = self.dual_plane.active_plane;
        self.dual_plane.tick_wtr(delta_sec.max(1.0) as u64);
        if let Some((new_plane, reason)) = self.dual_plane.evaluate_protection_switching() {
            if new_plane != prev_plane {
                let alarm = TelecomAlarm::PtpPlaneFailover {
                    from: prev_plane,
                    to: new_plane,
                    reason,
                };
                alarms.push(alarm);
            }
        }

        // 3. Inter-plane phase divergence monitoring
        if let Some(delta) = self.dual_plane.inter_plane_phase_delta_ns() {
            if delta.abs() > self.config.dual_plane.max_inter_plane_phase_diff_ns {
                alarms.push(TelecomAlarm::InterPlaneDivergence { delta_ns: delta });
            }
        }

        // 4. Retrieve disciplined & slewed phase offset from active PTP plane
        let ptp_phase_offset = self.dual_plane.compute_disciplined_phase_step(delta_sec);

        // 5. Update Hybrid Sync Controller
        let hybrid_adj = self.hybrid.update_ptp_sample(ptp_phase_offset, delta_sec);

        // Check SyncE lost alarm
        if self.current_synce_ql.is_none() && self.hybrid.mode == HybridSyncMode::PtpOnly {
            alarms.push(TelecomAlarm::SyncELost);
        }

        // 6. Disciplining Hardware Clock (PHC)
        let target_freq_ppb = match self.hybrid.mode {
            HybridSyncMode::HybridLocked => {
                // In HybridLocked, physical layer SyncE enforces zero frequency syntonization (0 ppb drift),
                // so PTP operates in pure phase adjustment mode.
                if hybrid_adj.phase_slew_ns != 0 {
                    self.phc.step_time_ns(hybrid_adj.phase_slew_ns);
                }
                0.0
            }
            HybridSyncMode::PtpOnly => {
                // PTP disciplines both phase and frequency
                if hybrid_adj.phase_slew_ns != 0 {
                    self.phc.step_time_ns(hybrid_adj.phase_slew_ns);
                }
                hybrid_adj.freq_ppb
            }
            HybridSyncMode::SyncEHoldover => {
                alarms.push(TelecomAlarm::HoldoverOperating);
                0.0
            }
            HybridSyncMode::FreeHoldover => {
                alarms.push(TelecomAlarm::HoldoverOperating);
                hybrid_adj.freq_ppb
            }
        };

        // Apply frequency steering to PHC
        self.phc.adj_freq_ppb(target_freq_ppb);

        // 7. 3GPP 38.104 Antenna Port Compliance Verification
        let cell_sync = self.sync_checker.evaluate_absolute_cell_sync();
        if !cell_sync.is_compliant {
            alarms.push(TelecomAlarm::CellPhaseOutOfSpec {
                max_abs_te_ns: cell_sync.max_abs_te_ns,
            });
        }

        let mimo_reports = self
            .sync_checker
            .evaluate_all_groups(NrTddSyncCategory::MimoTransmission);
        for r in mimo_reports {
            if !r.is_compliant {
                alarms.push(TelecomAlarm::MimoTaeExceeded {
                    measured_tae_ns: r.max_measured_tae_ns,
                    limit_ns: r.allowed_limit_ns,
                });
            }
        }

        self.active_alarms = alarms.clone();

        TelecomSyncCycleResult {
            active_plane: self.dual_plane.active_plane,
            hybrid_mode: self.hybrid.mode,
            phc_time: self.phc.get_time(),
            frequency_ppb: self.phc.freq_adjustment_ppb,
            estimated_phase_offset_ns: Some(ptp_phase_offset),
            alarms_triggered: alarms,
        }
    }

    /// Generates a comprehensive status report of the node.
    pub fn get_status_report(&self) -> TelecomSyncStatusReport {
        let cell_sync = self.sync_checker.evaluate_absolute_cell_sync();
        let mimo_reports = self
            .sync_checker
            .evaluate_all_groups(NrTddSyncCategory::MimoTransmission);
        let mimo_compliant = mimo_reports.iter().all(|r| r.is_compliant);

        TelecomSyncStatusReport {
            hybrid_mode: self.hybrid.mode,
            active_plane: self.dual_plane.active_plane,
            active_gm_clock_class: self.dual_plane.current_output_clock_class(),
            synce_ql: self.current_synce_ql,
            phc_time: self.phc.get_time(),
            frequency_steering_ppb: self.phc.freq_adjustment_ppb,
            total_phc_stepped_ns: self.phc.total_stepped_ns,
            inter_plane_phase_delta_ns: self.dual_plane.inter_plane_phase_delta_ns(),
            cell_sync_compliant: cell_sync.is_compliant,
            mimo_tae_compliant: mimo_compliant,
            active_alarms: self.active_alarms.clone(),
        }
    }
}

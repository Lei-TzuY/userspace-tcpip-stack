//! PTP Dual-Plane Redundancy & Hitless Protection Switching (ITU-T G.8275.1 / G.8273.2 / O-RAN).
//!
//! Implements high-availability dual-plane timing architecture for 5G O-RAN Fronthaul
//! (O-DU / O-RU) and Telecom Boundary Clocks. Concurrently tracks Primary (Plane A) and
//! Secondary (Plane B) Grandmasters, monitors inter-plane phase delta in real-time, executes
//! autonomous protection switching on failure/degradation, and applies hitless phase slewing
//! (ITU-T G.8273.2 Section 7.1) to avoid RF carrier dropouts.

use crate::ptp_pdv_filter::{PtpPdvFloorFilter, PtpTimestampSample};

/// PTP Redundancy Plane Identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PtpPlaneId {
    PlaneA,
    PlaneB,
}

impl PtpPlaneId {
    /// Returns the alternate redundancy plane.
    pub fn alternate(&self) -> Self {
        match self {
            PtpPlaneId::PlaneA => PtpPlaneId::PlaneB,
            PtpPlaneId::PlaneB => PtpPlaneId::PlaneA,
        }
    }
}

/// Protection Switching Revertive Operating Mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProtectionSwitchMode {
    /// Automatically switch back to Primary (Plane A) after restoration and WTR timer expiry
    #[default]
    Revertive,
    /// Remain on current active plane even after alternate plane recovers
    NonRevertive,
}

/// Operational state of an individual redundancy plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtpPlaneState {
    /// Actively driving system phase/time synchronization
    Active,
    /// Hot-standby tracking backup grandmaster in real-time
    Standby,
    /// Degraded or failed (Announce timeout, class degradation, or PDV floor collapse)
    Failed,
    /// Recovered but waiting out Wait-To-Restore (WTR) flap-damping duration
    Wtr,
}

/// Root cause trigger for a protection switchover event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchReason {
    InitialSelection,
    SignalLoss,
    ClockClassDegraded,
    FloorRateDegraded,
    PhaseSurge,
    ManualForced,
    WtrExpired,
}

/// Dynamic Announce and PTP tracking dataset for a single plane.
#[derive(Debug, Clone)]
pub struct PlaneDataset {
    pub plane_id: PtpPlaneId,
    pub clock_class: u8,
    pub clock_accuracy: u8,
    pub steps_removed: u16,
    pub announce_valid: bool,
    pub filter: PtpPdvFloorFilter,
    pub healthy: bool,
    pub last_filtered_offset_ns: i64,
}

impl PlaneDataset {
    pub fn new(plane_id: PtpPlaneId, filter: PtpPdvFloorFilter) -> Self {
        Self {
            plane_id,
            clock_class: 248, // Default freerun
            clock_accuracy: 0xFE,
            steps_removed: 0,
            announce_valid: false,
            filter,
            healthy: false,
            last_filtered_offset_ns: 0,
        }
    }
}

/// Configuration parameters for Dual-Plane Redundancy.
#[derive(Debug, Clone, PartialEq)]
pub struct DualPlaneConfig {
    /// Revertive vs NonRevertive behavior
    pub switch_mode: ProtectionSwitchMode,
    /// Wait-To-Restore damping duration in seconds
    pub wtr_period_secs: u64,
    /// Maximum allowable phase difference between Plane A and Plane B before alarm (ns)
    pub max_inter_plane_phase_diff_ns: i64,
    /// Maximum allowed phase slew rate during switchover (ns/s, G.8273.2 <= 50 ns/s)
    pub max_switchover_slew_ns_per_sec: i64,
    /// Minimum floor packet rate required to consider plane healthy (%)
    pub min_floor_rate_percent: f64,
    /// Floor width window (ns) for evaluating packet rate adequacy
    pub floor_width_ns: i64,
}

impl Default for DualPlaneConfig {
    fn default() -> Self {
        Self {
            switch_mode: ProtectionSwitchMode::Revertive,
            wtr_period_secs: 60,                // 60-second standard WTR
            max_inter_plane_phase_diff_ns: 100, // 100 ns telecom divergence alarm
            max_switchover_slew_ns_per_sec: 50, // 50 ns/s hitless slew limit
            min_floor_rate_percent: 10.0,
            floor_width_ns: 100,
        }
    }
}

/// Real-time Dual-Plane Status and Diagnostics Telemetry.
#[derive(Debug, Clone, PartialEq)]
pub struct DualPlaneMetrics {
    pub active_plane: PtpPlaneId,
    pub plane_a_state: PtpPlaneState,
    pub plane_b_state: PtpPlaneState,
    pub inter_plane_phase_delta_ns: Option<i64>,
    pub pending_phase_jump_ns: i64,
    pub total_switch_events: usize,
    pub last_switch_reason: Option<SwitchReason>,
    pub active_clock_class: u8,
}

/// PTP Dual-Plane Redundancy & Hitless Protection Switching Controller.
#[derive(Debug, Clone)]
pub struct DualPlaneEngine {
    pub config: DualPlaneConfig,
    pub plane_a: PlaneDataset,
    pub plane_b: PlaneDataset,
    pub active_plane: PtpPlaneId,
    pub wtr_timer_secs: u64,
    pub pending_phase_jump_ns: i64,
    pub total_switch_events: usize,
    pub last_switch_reason: Option<SwitchReason>,
}

impl DualPlaneEngine {
    pub fn new(
        config: DualPlaneConfig,
        filter_a: PtpPdvFloorFilter,
        filter_b: PtpPdvFloorFilter,
    ) -> Self {
        Self {
            config,
            plane_a: PlaneDataset::new(PtpPlaneId::PlaneA, filter_a),
            plane_b: PlaneDataset::new(PtpPlaneId::PlaneB, filter_b),
            active_plane: PtpPlaneId::PlaneA,
            wtr_timer_secs: 0,
            pending_phase_jump_ns: 0,
            total_switch_events: 0,
            last_switch_reason: None,
        }
    }

    /// Ingests a new PTP timestamp sample into the designated plane's PDV floor filter.
    pub fn push_plane_sample(&mut self, plane: PtpPlaneId, sample: PtpTimestampSample) {
        let dataset = match plane {
            PtpPlaneId::PlaneA => &mut self.plane_a,
            PtpPlaneId::PlaneB => &mut self.plane_b,
        };
        dataset.filter.push_sample(sample);
        if let Some(estimate) = dataset.filter.compute_estimate() {
            dataset.last_filtered_offset_ns = estimate.estimated_offset_ns;
        }
        self.evaluate_plane_health(plane);
    }

    /// Updates Announce message dataset attributes for a plane.
    pub fn update_plane_announce(
        &mut self,
        plane: PtpPlaneId,
        clock_class: u8,
        clock_accuracy: u8,
        steps_removed: u16,
    ) {
        let dataset = match plane {
            PtpPlaneId::PlaneA => &mut self.plane_a,
            PtpPlaneId::PlaneB => &mut self.plane_b,
        };
        dataset.clock_class = clock_class;
        dataset.clock_accuracy = clock_accuracy;
        dataset.steps_removed = steps_removed;
        dataset.announce_valid = true;
        self.evaluate_plane_health(plane);
    }

    /// Signals signal loss or Announce timeout on a plane.
    pub fn notify_plane_signal_loss(&mut self, plane: PtpPlaneId) {
        let dataset = match plane {
            PtpPlaneId::PlaneA => &mut self.plane_a,
            PtpPlaneId::PlaneB => &mut self.plane_b,
        };
        dataset.announce_valid = false;
        dataset.healthy = false;
    }

    /// Evaluates health status for a single redundancy plane.
    pub fn evaluate_plane_health(&mut self, plane: PtpPlaneId) -> bool {
        let dataset = match plane {
            PtpPlaneId::PlaneA => &mut self.plane_a,
            PtpPlaneId::PlaneB => &mut self.plane_b,
        };

        if !dataset.announce_valid {
            dataset.healthy = false;
            return false;
        }

        // Clock class check: class > 135 (e.g. 140 or 248) is degraded
        if dataset.clock_class > 135 {
            dataset.healthy = false;
            return false;
        }

        // Floor packet rate adequacy
        let floor_adequate = dataset.filter.is_floor_rate_adequate(
            self.config.min_floor_rate_percent,
            self.config.floor_width_ns,
        );

        dataset.healthy = floor_adequate;
        dataset.healthy
    }

    /// Computes the real-time inter-plane phase delta: (Offset_A - Offset_B) in nanoseconds.
    pub fn inter_plane_phase_delta_ns(&self) -> Option<i64> {
        if self.plane_a.healthy && self.plane_b.healthy {
            Some(self.plane_a.last_filtered_offset_ns - self.plane_b.last_filtered_offset_ns)
        } else {
            None
        }
    }

    /// Checks if inter-plane phase delta exceeds allowable telecom divergence alarm limit.
    pub fn is_inter_plane_diverged(&self) -> bool {
        if let Some(delta) = self.inter_plane_phase_delta_ns() {
            delta.abs() > self.config.max_inter_plane_phase_diff_ns
        } else {
            false
        }
    }

    /// Evaluates multi-criteria protection switching triggers and executes switchover if needed.
    pub fn evaluate_protection_switching(&mut self) -> Option<(PtpPlaneId, SwitchReason)> {
        let active = self.active_plane;
        let standby = active.alternate();

        let active_healthy = match active {
            PtpPlaneId::PlaneA => self.plane_a.healthy,
            PtpPlaneId::PlaneB => self.plane_b.healthy,
        };

        let standby_healthy = match standby {
            PtpPlaneId::PlaneA => self.plane_a.healthy,
            PtpPlaneId::PlaneB => self.plane_b.healthy,
        };

        // Failure trigger evaluation
        if !active_healthy && standby_healthy {
            let reason = {
                let active_ds = match active {
                    PtpPlaneId::PlaneA => &self.plane_a,
                    PtpPlaneId::PlaneB => &self.plane_b,
                };
                if !active_ds.announce_valid {
                    SwitchReason::SignalLoss
                } else if active_ds.clock_class > 135 {
                    SwitchReason::ClockClassDegraded
                } else {
                    SwitchReason::FloorRateDegraded
                }
            };
            self.execute_switchover(standby, reason);
            return Some((standby, reason));
        }

        // Quality arbitration (G.8275.1 Alternate BMCA):
        // If both are healthy, check if standby has strictly better clock class
        if active_healthy && standby_healthy {
            let (active_class, standby_class) = match active {
                PtpPlaneId::PlaneA => (self.plane_a.clock_class, self.plane_b.clock_class),
                PtpPlaneId::PlaneB => (self.plane_b.clock_class, self.plane_a.clock_class),
            };

            if standby_class < active_class {
                self.execute_switchover(standby, SwitchReason::ClockClassDegraded);
                return Some((standby, SwitchReason::ClockClassDegraded));
            }
        }

        None
    }

    /// Executes the switchover to `target_plane`, absorbing inter-plane phase delta.
    fn execute_switchover(&mut self, target_plane: PtpPlaneId, reason: SwitchReason) {
        let old_active = self.active_plane;
        if old_active == target_plane {
            return;
        }

        let old_offset = match old_active {
            PtpPlaneId::PlaneA => self.plane_a.last_filtered_offset_ns,
            PtpPlaneId::PlaneB => self.plane_b.last_filtered_offset_ns,
        };
        let new_offset = match target_plane {
            PtpPlaneId::PlaneA => self.plane_a.last_filtered_offset_ns,
            PtpPlaneId::PlaneB => self.plane_b.last_filtered_offset_ns,
        };

        // Phase jump to be smoothly slewed across transition
        let phase_jump = new_offset - old_offset;
        self.pending_phase_jump_ns += phase_jump;

        self.active_plane = target_plane;
        self.total_switch_events += 1;
        self.last_switch_reason = Some(reason);
        self.wtr_timer_secs = 0;
    }

    /// Calculates the disciplined phase adjustment to feed into the local clock servo,
    /// applying hitless phase slewing to absorb switchover jumps without phase shocks.
    pub fn compute_disciplined_phase_step(&mut self, interval_sec: f64) -> i64 {
        let dt = interval_sec.max(0.001);
        let max_slew = ((self.config.max_switchover_slew_ns_per_sec as f64) * dt).ceil() as i64;
        let max_slew = max_slew.max(1);

        // Raw phase offset from the active plane
        let active_offset = match self.active_plane {
            PtpPlaneId::PlaneA => self.plane_a.last_filtered_offset_ns,
            PtpPlaneId::PlaneB => self.plane_b.last_filtered_offset_ns,
        };

        // Slew pending phase jump towards 0
        if self.pending_phase_jump_ns != 0 {
            let slew_amount = self.pending_phase_jump_ns.clamp(-max_slew, max_slew);
            self.pending_phase_jump_ns -= slew_amount;
            active_offset + slew_amount
        } else {
            active_offset
        }
    }

    /// Advances the Wait-To-Restore (WTR) flap-damping timer by `elapsed_secs`.
    ///
    /// In Revertive mode, when Plane A recovers, it enters WTR state until `wtr_period_secs`
    /// expires, preventing flapping before restoring Plane A to Active.
    pub fn tick_wtr(&mut self, elapsed_secs: u64) -> bool {
        if self.config.switch_mode != ProtectionSwitchMode::Revertive {
            return false;
        }

        // Only tick WTR if Plane B is currently Active and Plane A is healthy
        if self.active_plane == PtpPlaneId::PlaneB && self.plane_a.healthy {
            self.wtr_timer_secs += elapsed_secs;
            if self.wtr_timer_secs >= self.config.wtr_period_secs {
                self.execute_switchover(PtpPlaneId::PlaneA, SwitchReason::WtrExpired);
                return true;
            }
        } else {
            self.wtr_timer_secs = 0;
        }
        false
    }

    /// Returns current state for a specific redundancy plane.
    pub fn plane_state(&self, plane: PtpPlaneId) -> PtpPlaneState {
        let (is_active, healthy) = match plane {
            PtpPlaneId::PlaneA => (
                self.active_plane == PtpPlaneId::PlaneA,
                self.plane_a.healthy,
            ),
            PtpPlaneId::PlaneB => (
                self.active_plane == PtpPlaneId::PlaneB,
                self.plane_b.healthy,
            ),
        };

        if !healthy {
            PtpPlaneState::Failed
        } else if is_active {
            PtpPlaneState::Active
        } else if plane == PtpPlaneId::PlaneA
            && self.config.switch_mode == ProtectionSwitchMode::Revertive
            && self.wtr_timer_secs > 0
        {
            PtpPlaneState::Wtr
        } else {
            PtpPlaneState::Standby
        }
    }

    /// Returns the advertised clock class of the currently active plane.
    pub fn current_output_clock_class(&self) -> u8 {
        match self.active_plane {
            PtpPlaneId::PlaneA => {
                if self.plane_a.healthy {
                    self.plane_a.clock_class
                } else {
                    248
                }
            }
            PtpPlaneId::PlaneB => {
                if self.plane_b.healthy {
                    self.plane_b.clock_class
                } else {
                    248
                }
            }
        }
    }

    /// Gathers comprehensive dual-plane telemetry metrics.
    pub fn metrics(&self) -> DualPlaneMetrics {
        DualPlaneMetrics {
            active_plane: self.active_plane,
            plane_a_state: self.plane_state(PtpPlaneId::PlaneA),
            plane_b_state: self.plane_state(PtpPlaneId::PlaneB),
            inter_plane_phase_delta_ns: self.inter_plane_phase_delta_ns(),
            pending_phase_jump_ns: self.pending_phase_jump_ns,
            total_switch_events: self.total_switch_events,
            last_switch_reason: self.last_switch_reason,
            active_clock_class: self.current_output_clock_class(),
        }
    }
}

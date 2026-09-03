//! SyncE + PTP Hybrid Synchronization Controller (ITU-T G.8273.2 Annex C / G.8275.1).
//!
//! Integrates physical layer Synchronous Ethernet (SyncE ITU-T G.8262 / G.8264 ESMC) frequency
//! syntonization with packet-layer PTP (ITU-T G.8275.1 / G.8275.2) phase/time synchronization.
//!
//! Under hybrid operation, the physical layer recovered clock provides continuous Stratum-1
//! traceable frequency lock, zeroing local oscillator drift and allowing the PTP PLL to operate
//! in phase-only correction mode without packet-induced frequency wander. If SyncE or PTP
//! degrades, the engine automatically transitions through a multi-mode failover matrix
//! with hitless phase slew-rate limiting (ITU-T G.8273.2).

use crate::ptp_pdv_filter::{
    PtpClockServo, PtpClockServoConfig, PtpClockServoState, PtpServoAction,
};
use crate::synce_esmc::QualityLevel;

/// Hybrid Synchronization Operating Mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HybridSyncMode {
    /// Full Hybrid Lock: Frequency locked to SyncE physical clock, Phase locked to PTP
    HybridLocked,
    /// PTP-Only Fallback: SyncE lost/DNU; dual frequency + phase steering via PTP packet servo
    PtpOnly,
    /// SyncE Holdover: PTP packets lost/congested; frequency syntonized to SyncE physical line rate
    SyncEHoldover,
    /// Free-Running Holdover: Both SyncE and PTP lost; local oscillator aging holdover
    FreeHoldover,
}

/// Configuration parameters for the Hybrid Synchronization Controller.
#[derive(Debug, Clone, PartialEq)]
pub struct HybridSyncConfig {
    /// Minimum acceptable SyncE Quality Level (e.g. QL-SEC or better)
    pub min_synce_ql: QualityLevel,
    /// Maximum allowed phase slew rate in nanoseconds per second (ITU-T G.8273.2 limit is <= 50 ns/s)
    pub max_phase_slew_ns_per_sec: i64,
    /// Target phase error bound (ns) to declare phase lock
    pub phase_lock_threshold_ns: i64,
    /// Maximum allowable holdover time in seconds within 1.5 µs specification
    pub max_holdover_secs: u64,
    /// Local oscillator nominal drift in parts-per-billion (ppb = ns/s)
    pub oscillator_drift_ppb: f64,
    /// PTP Clock Servo configuration when operating in PTP-only fallback mode
    pub servo_config: PtpClockServoConfig,
}

impl Default for HybridSyncConfig {
    fn default() -> Self {
        Self {
            min_synce_ql: QualityLevel::QlSec,
            max_phase_slew_ns_per_sec: 50, // 50 ns/s standard telecom limit
            phase_lock_threshold_ns: 50,   // 50 ns target
            max_holdover_secs: 14400,      // 4 hours
            oscillator_drift_ppb: 10.0,    // 10 ppb
            servo_config: PtpClockServoConfig::default(),
        }
    }
}

/// Output adjustment command produced by the Hybrid Controller.
#[derive(Debug, Clone, PartialEq)]
pub struct HybridAdjustment {
    /// Phase slewing adjustment applied to local clock in nanoseconds
    pub phase_slew_ns: i64,
    /// Frequency discipline offset in parts-per-billion (0.0 when syntonized to SyncE)
    pub freq_ppb: f64,
    /// Current operational mode
    pub mode: HybridSyncMode,
}

/// Real-time telemetry metrics for the Hybrid Synchronization Controller.
#[derive(Debug, Clone, PartialEq)]
pub struct HybridSyncMetrics {
    pub mode: HybridSyncMode,
    pub current_synce_ql: QualityLevel,
    pub synce_acceptable: bool,
    pub ptp_locked: bool,
    pub last_ptp_offset_ns: i64,
    pub accumulated_phase_correction_ns: i64,
    pub active_frequency_ppb: f64,
    pub holdover_duration_secs: u64,
    pub accumulated_holdover_drift_ns: i64,
    pub clock_class: u8,
}

/// SyncE + PTP Hybrid Synchronization Controller Engine (ITU-T G.8273.2 Annex C).
#[derive(Debug, Clone)]
pub struct HybridSyncEngine {
    pub config: HybridSyncConfig,
    pub mode: HybridSyncMode,
    pub current_synce_ql: QualityLevel,
    pub synce_valid: bool,
    pub ptp_servo: PtpClockServo,
    pub last_ptp_offset_ns: i64,
    pub accumulated_phase_correction_ns: i64,
    pub holdover_duration_secs: u64,
    pub accumulated_holdover_drift_ns: i64,
}

impl HybridSyncEngine {
    pub fn new(config: HybridSyncConfig) -> Self {
        let servo = PtpClockServo::new(config.servo_config.clone());
        Self {
            config,
            mode: HybridSyncMode::FreeHoldover,
            current_synce_ql: QualityLevel::QlInvalid,
            synce_valid: false,
            ptp_servo: servo,
            last_ptp_offset_ns: 0,
            accumulated_phase_correction_ns: 0,
            holdover_duration_secs: 0,
            accumulated_holdover_drift_ns: 0,
        }
    }

    /// Checks if the current SyncE SSM Quality Level meets configuration standards.
    pub fn is_synce_acceptable(&self) -> bool {
        if !self.synce_valid {
            return false;
        }
        if self.current_synce_ql == QualityLevel::QlDnu
            || self.current_synce_ql == QualityLevel::QlInvalid
        {
            return false;
        }
        self.current_synce_ql.rank() <= self.config.min_synce_ql.rank()
    }

    /// Updates physical layer SyncE status and received ESMC SSM Quality Level.
    pub fn update_synce(&mut self, ql: QualityLevel, valid: bool) {
        self.current_synce_ql = ql;
        self.synce_valid = valid;
        self.evaluate_mode();
    }

    /// Re-evaluates hybrid operating mode based on SyncE and PTP status.
    fn evaluate_mode(&mut self) {
        let synce_ok = self.is_synce_acceptable();
        let ptp_ok =
            self.ptp_servo.is_locked() || self.ptp_servo.state() == PtpClockServoState::Aligning;

        let prev_mode = self.mode;
        self.mode = match (synce_ok, ptp_ok) {
            (true, true) => HybridSyncMode::HybridLocked,
            (false, true) => HybridSyncMode::PtpOnly,
            (true, false) => HybridSyncMode::SyncEHoldover,
            (false, false) => HybridSyncMode::FreeHoldover,
        };

        if self.mode == HybridSyncMode::HybridLocked || self.mode == HybridSyncMode::PtpOnly {
            self.holdover_duration_secs = 0;
            self.accumulated_holdover_drift_ns = 0;
        } else if prev_mode != self.mode {
            // Mode switched into holdover
            self.holdover_duration_secs = 0;
        }
    }

    /// Ingests a new PTP filtered phase error offset and calculates local clock adjustment.
    ///
    /// # Arguments
    /// - `offset_ns`: Measured time error in nanoseconds (t_master - t_slave)
    /// - `interval_sec`: Sample interval in seconds (e.g. 0.0625s)
    pub fn update_ptp_sample(&mut self, offset_ns: i64, interval_sec: f64) -> HybridAdjustment {
        self.last_ptp_offset_ns = offset_ns;
        let dt = interval_sec.max(0.001);

        // Update underlying PTP servo state
        let servo_action = self.ptp_servo.sample(offset_ns, interval_sec);
        self.evaluate_mode();

        match self.mode {
            HybridSyncMode::HybridLocked => {
                // In Hybrid mode, SyncE provides zero-frequency drift syntonization.
                // We slew phase towards 0 while strictly respecting the G.8273.2 max slew rate limit.
                let max_slew = ((self.config.max_phase_slew_ns_per_sec as f64) * dt).ceil() as i64;
                let max_slew = max_slew.max(1);

                let phase_slew = offset_ns.clamp(-max_slew, max_slew);
                self.accumulated_phase_correction_ns += phase_slew;

                HybridAdjustment {
                    phase_slew_ns: phase_slew,
                    freq_ppb: 0.0, // Physical layer line rate clock locked by SyncE
                    mode: self.mode,
                }
            }
            HybridSyncMode::PtpOnly => {
                // SyncE unavailable; full PI frequency + phase steering via PTP
                match servo_action {
                    PtpServoAction::Step { step_ns } => {
                        self.accumulated_phase_correction_ns += step_ns;
                        HybridAdjustment {
                            phase_slew_ns: step_ns,
                            freq_ppb: self.ptp_servo.current_freq_ppb(),
                            mode: self.mode,
                        }
                    }
                    PtpServoAction::AdjustFreq {
                        freq_ppb,
                        phase_adjust_ns,
                    } => {
                        let max_slew =
                            ((self.config.max_phase_slew_ns_per_sec as f64) * dt).ceil() as i64;
                        let max_slew = max_slew.max(1);
                        let phase_slew = phase_adjust_ns.clamp(-max_slew, max_slew);
                        self.accumulated_phase_correction_ns += phase_slew;

                        HybridAdjustment {
                            phase_slew_ns: phase_slew,
                            freq_ppb,
                            mode: self.mode,
                        }
                    }
                    PtpServoAction::Holdover { drift_ppb } => HybridAdjustment {
                        phase_slew_ns: 0,
                        freq_ppb: drift_ppb,
                        mode: self.mode,
                    },
                }
            }
            HybridSyncMode::SyncEHoldover => {
                // PTP lost, but SyncE frequency is fully intact
                HybridAdjustment {
                    phase_slew_ns: 0,
                    freq_ppb: 0.0, // SyncE maintains exact physical frequency
                    mode: self.mode,
                }
            }
            HybridSyncMode::FreeHoldover => {
                // Both lost
                HybridAdjustment {
                    phase_slew_ns: 0,
                    freq_ppb: self.ptp_servo.current_freq_ppb(),
                    mode: self.mode,
                }
            }
        }
    }

    /// Handles loss or timeout of PTP packet updates, transitioning into Holdover.
    pub fn notify_ptp_timeout(&mut self) {
        self.ptp_servo.enter_holdover();
        self.evaluate_mode();
    }

    /// Advances holdover time by `elapsed_secs`.
    pub fn tick_holdover(&mut self, elapsed_secs: u64) {
        if self.mode == HybridSyncMode::SyncEHoldover {
            // Frequency is locked to SyncE (wander generation <= 0.25 ns / G.8262), virtually 0 drift
            self.holdover_duration_secs += elapsed_secs;
        } else if self.mode == HybridSyncMode::FreeHoldover {
            self.holdover_duration_secs += elapsed_secs;
            let drift = (self.config.oscillator_drift_ppb * elapsed_secs as f64).round() as i64;
            self.accumulated_holdover_drift_ns += drift;
        }
    }

    /// Returns the advertised PTP Clock Class based on hybrid operational state.
    pub fn current_clock_class(&self) -> u8 {
        match self.mode {
            HybridSyncMode::HybridLocked => 6, // PRTC locked equivalent
            HybridSyncMode::PtpOnly => {
                if self.ptp_servo.is_locked() {
                    7 // Locked to packet grandmaster
                } else {
                    135 // Aligning / degraded
                }
            }
            HybridSyncMode::SyncEHoldover => {
                // Frequency is Stratum-1 locked via SyncE! Excellent holdover
                7
            }
            HybridSyncMode::FreeHoldover => {
                if self.holdover_duration_secs <= self.config.max_holdover_secs {
                    7 // Within specification
                } else {
                    140 // Out of specification
                }
            }
        }
    }

    /// Gathers real-time hybrid metrics and diagnostic telemetry.
    pub fn metrics(&self) -> HybridSyncMetrics {
        let active_freq = match self.mode {
            HybridSyncMode::HybridLocked | HybridSyncMode::SyncEHoldover => 0.0,
            HybridSyncMode::PtpOnly | HybridSyncMode::FreeHoldover => {
                self.ptp_servo.current_freq_ppb()
            }
        };

        HybridSyncMetrics {
            mode: self.mode,
            current_synce_ql: self.current_synce_ql,
            synce_acceptable: self.is_synce_acceptable(),
            ptp_locked: self.ptp_servo.is_locked(),
            last_ptp_offset_ns: self.last_ptp_offset_ns,
            accumulated_phase_correction_ns: self.accumulated_phase_correction_ns,
            active_frequency_ppb: active_freq,
            holdover_duration_secs: self.holdover_duration_secs,
            accumulated_holdover_drift_ns: self.accumulated_holdover_drift_ns,
            clock_class: self.current_clock_class(),
        }
    }
}

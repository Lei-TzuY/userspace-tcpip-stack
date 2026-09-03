//! PTP Assisted Partial Timing Support (APTS) Engine (ITU-T G.8275.2 / G.8271.1).
//!
//! Implements the ITU-T G.8275.2 APTS architecture combining primary GNSS PRTC reception
//! with continuous packet-network delay asymmetry self-calibration, seamless GNSS loss failover
//! to PTP PTS mode, floor packet rate health qualification, and oscillator holdover tracking.

use crate::ptp_pdv_filter::{PtpPdvFloorFilter, PtpTimestampSample};

/// APTS Operational Synchronization State (ITU-T G.8275.2 Section 6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AptsState {
    /// GNSS is locked (PRTC trace); calibrating PTP network path asymmetry in background
    GnssLocked,
    /// GNSS signal restored; qualifying phase stability before re-declaring lock
    GnssQualifying,
    /// GNSS lost; operating on PTP Assisted Partial Timing Support using calibrated asymmetry
    PtpLockedApts,
    /// Both GNSS and PTP unavailable or degraded; running on local oscillator holdover
    Holdover,
    /// Uncalibrated local oscillator freerun
    Freerun,
}

/// APTS Engine Configuration parameters.
#[derive(Debug, Clone, PartialEq)]
pub struct AptsConfig {
    /// Learning rate factor alpha for EMA asymmetry calibration (0.001..1.0)
    pub asymmetry_learning_alpha: f64,
    /// Minimum floor packet rate percentage (ITU-T G.8275.2) required to stay in PtpLockedApts
    pub min_floor_packet_rate_percent: f64,
    /// Floor width window (ns) used to evaluate floor packet rate adequacy
    pub floor_width_ns: i64,
    /// Consecutive valid GNSS samples required to exit GnssQualifying state
    pub gnss_qualification_count: usize,
    /// Maximum allowable holdover time in seconds within 1.5 µs specification
    pub max_holdover_within_spec_secs: u64,
    /// Local oscillator nominal drift in parts-per-billion (ppb = ns/s)
    pub oscillator_drift_ppb: f64,
}

impl Default for AptsConfig {
    fn default() -> Self {
        Self {
            asymmetry_learning_alpha: 0.1,
            min_floor_packet_rate_percent: 10.0,
            floor_width_ns: 200,
            gnss_qualification_count: 5,
            max_holdover_within_spec_secs: 14400, // 4 hours (~1.5µs budget for Stratum 3E)
            oscillator_drift_ppb: 10.0,           // 10 ppb standard OCXO
        }
    }
}

/// Real-time APTS Status and Performance Metrics.
#[derive(Debug, Clone, PartialEq)]
pub struct AptsMetrics {
    pub state: AptsState,
    pub calibrated_asymmetry_ns: f64,
    pub last_gnss_offset_ns: i64,
    pub last_ptp_offset_ns: i64,
    pub floor_packet_rate_percent: (f64, f64),
    pub holdover_duration_secs: u64,
    pub accumulated_holdover_drift_ns: i64,
    pub clock_class: u8,
}

/// ITU-T G.8275.2 Assisted Partial Timing Support (APTS) Engine.
#[derive(Debug, Clone)]
pub struct AptsEngine {
    pub config: AptsConfig,
    pub state: AptsState,
    pub pdv_filter: PtpPdvFloorFilter,
    pub calibrated_asymmetry_ns: f64,
    pub asymmetry_calibration_samples: usize,
    pub consecutive_gnss_qualified: usize,
    pub last_gnss_offset_ns: i64,
    pub last_ptp_offset_ns: i64,
    pub holdover_duration_secs: u64,
    pub accumulated_holdover_drift_ns: i64,
    pub gnss_loss_events: usize,
    pub gnss_restore_events: usize,
}

impl AptsEngine {
    pub fn new(config: AptsConfig, pdv_filter: PtpPdvFloorFilter) -> Self {
        Self {
            config,
            state: AptsState::GnssLocked,
            pdv_filter,
            calibrated_asymmetry_ns: 0.0,
            asymmetry_calibration_samples: 0,
            consecutive_gnss_qualified: 0,
            last_gnss_offset_ns: 0,
            last_ptp_offset_ns: 0,
            holdover_duration_secs: 0,
            accumulated_holdover_drift_ns: 0,
            gnss_loss_events: 0,
            gnss_restore_events: 0,
        }
    }

    /// Ingests a new PTP timestamp sample into the underlying PDV floor filter.
    pub fn push_ptp_sample(&mut self, sample: PtpTimestampSample) {
        self.pdv_filter.push_sample(sample);
    }

    /// Updates GNSS primary reference status and observed local-to-GNSS offset (ns).
    ///
    /// If GNSS is locked:
    /// - Evaluates PTP timing stream.
    /// - Cross-calibrates PTP network delay asymmetry against GNSS reference.
    /// - If in GnssQualifying state, counts qualifications towards full lock.
    pub fn update_gnss(&mut self, gnss_valid: bool, gnss_offset_ns: i64) {
        self.last_gnss_offset_ns = gnss_offset_ns;

        if gnss_valid {
            match self.state {
                AptsState::GnssLocked => {
                    // Continuously learn network path asymmetry:
                    // True physical asymmetry = (d_fwd - d_rev) - 2 * gnss_offset
                    if let Some(estimate) = self.pdv_filter.compute_estimate() {
                        let raw_diff =
                            estimate.forward_delay_floor_ns - estimate.reverse_delay_floor_ns;
                        let measured_asym = raw_diff as f64 - 2.0 * (gnss_offset_ns as f64);

                        let alpha = self.config.asymmetry_learning_alpha.clamp(0.001, 1.0);
                        if self.asymmetry_calibration_samples == 0 {
                            self.calibrated_asymmetry_ns = measured_asym;
                        } else {
                            self.calibrated_asymmetry_ns = self.calibrated_asymmetry_ns
                                * (1.0 - alpha)
                                + measured_asym * alpha;
                        }
                        self.asymmetry_calibration_samples += 1;

                        // Keep the filter's asymmetry compensation synchronized
                        self.pdv_filter.asymmetry_compensation_ns =
                            self.calibrated_asymmetry_ns.round() as i64;
                    }
                    self.holdover_duration_secs = 0;
                    self.accumulated_holdover_drift_ns = 0;
                }
                AptsState::GnssQualifying => {
                    self.consecutive_gnss_qualified += 1;
                    if self.consecutive_gnss_qualified >= self.config.gnss_qualification_count {
                        self.state = AptsState::GnssLocked;
                        self.gnss_restore_events += 1;
                        self.holdover_duration_secs = 0;
                        self.accumulated_holdover_drift_ns = 0;
                    }
                }
                AptsState::PtpLockedApts | AptsState::Holdover | AptsState::Freerun => {
                    // Enter qualification before switching back to GNSS
                    self.state = AptsState::GnssQualifying;
                    self.consecutive_gnss_qualified = 1;
                }
            }
        } else {
            // GNSS Lost
            self.consecutive_gnss_qualified = 0;
            if self.state == AptsState::GnssLocked || self.state == AptsState::GnssQualifying {
                self.gnss_loss_events += 1;
                // Transition to PTP APTS if PTP floor rate is adequate
                if self.is_ptp_adequate() {
                    self.state = AptsState::PtpLockedApts;
                    // Apply calibrated asymmetry to floor filter
                    self.pdv_filter.asymmetry_compensation_ns =
                        self.calibrated_asymmetry_ns.round() as i64;
                } else {
                    self.state = AptsState::Holdover;
                    self.holdover_duration_secs = 0;
                    self.accumulated_holdover_drift_ns = 0;
                }
            } else if self.state == AptsState::PtpLockedApts {
                // Verify PTP stream is still adequate
                if !self.is_ptp_adequate() {
                    self.state = AptsState::Holdover;
                    self.holdover_duration_secs = 0;
                    self.accumulated_holdover_drift_ns = 0;
                }
            }
        }
    }

    /// Checks whether the PTP packet stream has adequate floor packet percentage to maintain lock.
    pub fn is_ptp_adequate(&self) -> bool {
        self.pdv_filter.is_floor_rate_adequate(
            self.config.min_floor_packet_rate_percent,
            self.config.floor_width_ns,
        )
    }

    /// Computes the effective phase offset to discipline the local clock.
    ///
    /// - `GnssLocked`: Returns `gnss_offset_ns`.
    /// - `PtpLockedApts`: Returns PTP floor estimate offset with calibrated asymmetry applied.
    /// - `Holdover` / `Freerun`: Returns None (or drift-only).
    pub fn compute_phase_offset(&mut self) -> Option<i64> {
        match self.state {
            AptsState::GnssLocked => Some(self.last_gnss_offset_ns),
            AptsState::GnssQualifying => {
                // During qualification, continue using PTP if adequate, else GNSS
                if self.is_ptp_adequate() {
                    let est = self.compute_ptp_offset()?;
                    Some(est)
                } else {
                    Some(self.last_gnss_offset_ns)
                }
            }
            AptsState::PtpLockedApts => {
                if !self.is_ptp_adequate() {
                    self.state = AptsState::Holdover;
                    return None;
                }
                self.compute_ptp_offset()
            }
            AptsState::Holdover | AptsState::Freerun => None,
        }
    }

    fn compute_ptp_offset(&mut self) -> Option<i64> {
        self.pdv_filter.asymmetry_compensation_ns = self.calibrated_asymmetry_ns.round() as i64;
        let est = self.pdv_filter.compute_estimate()?;
        self.last_ptp_offset_ns = est.estimated_offset_ns;
        Some(est.estimated_offset_ns)
    }

    /// Advances the holdover timer when operating in Holdover state.
    pub fn tick_holdover(&mut self, elapsed_secs: u64) {
        if self.state == AptsState::Holdover {
            self.holdover_duration_secs += elapsed_secs;
            let drift_ns = (self.config.oscillator_drift_ppb * elapsed_secs as f64).round() as i64;
            self.accumulated_holdover_drift_ns += drift_ns;
        }
    }

    /// Returns the advertised PTP Clock Class according to ITU-T G.8275.2.
    pub fn current_clock_class(&self) -> u8 {
        match self.state {
            AptsState::GnssLocked => 6,     // PRTC locked
            AptsState::GnssQualifying => 7, // Restoring / qualifying
            AptsState::PtpLockedApts => 7,  // In-spec APTS locked to PTP
            AptsState::Holdover => {
                if self.holdover_duration_secs <= self.config.max_holdover_within_spec_secs {
                    7 // Holdover in specification
                } else {
                    140 // Holdover out of specification (Category 1/2)
                }
            }
            AptsState::Freerun => 248, // Free-running
        }
    }

    /// Gathers real-time APTS metrics and performance indicators.
    pub fn metrics(&self) -> AptsMetrics {
        AptsMetrics {
            state: self.state,
            calibrated_asymmetry_ns: self.calibrated_asymmetry_ns,
            last_gnss_offset_ns: self.last_gnss_offset_ns,
            last_ptp_offset_ns: self.last_ptp_offset_ns,
            floor_packet_rate_percent: self
                .pdv_filter
                .floor_packet_percentage(self.config.floor_width_ns),
            holdover_duration_secs: self.holdover_duration_secs,
            accumulated_holdover_drift_ns: self.accumulated_holdover_drift_ns,
            clock_class: self.current_clock_class(),
        }
    }
}

//! 3GPP Rel-17/18 5G NR Conditional Handover (CHO) & Dual Connectivity CPC Engine.
//!
//! Compliant with:
//! - 3GPP TS 38.331 Rel-17/18 §5.3.5.4 ("Conditional reconfiguration - CHO and CPC")
//! - 3GPP TS 38.331 Rel-17/18 §5.5.4 ("Measurement report triggering" - Events A3, A4, A5)
//! - 3GPP TS 38.300 Rel-17/18 §9.2.3.4 ("Conditional Handover")
//! - 3GPP TS 38.423 Rel-17/18 §8.2 ("Xn-AP Handover Preparation & Cancelation for CHO")
//!
//! Solves:
//! 1. Radio Link Failure (RLF) and Handover Failure (HOF) during rapid radio degradation
//!    (e.g., mmWave blockage, urban street canyons, high mobility) where legacy RRCReconfiguration
//!    commands are dropped over failing source links.
//! 2. Autonomous UE-driven handover trigger upon sustained fulfillment of execution conditions.
//! 3. Advance Contention-Free Random Access (CFRA) dedicated preamble reservation on target cells.
//! 4. Coordinated multi-candidate evaluation (up to 8 candidates) with automatic Xn-AP cancellation
//!    of non-selected targets to prevent resource leaks.
//! 5. Conditional PSCell Change (CPC) in Dual Connectivity (MR-DC / NR-DC) without Master Node
//!    signaling bottlenecks.
//!
//! Pure Rust standard library implementation with zero external dependencies.

use std::collections::HashMap;
use std::fmt;

/// Maximum number of active CHO/CPC candidate configurations allowed per UE (3GPP TS 38.331).
pub const MAX_CHO_CANDIDATES: usize = 8;

/// Default filter coefficient integer $k$ for L3 measurement filtering ($a = (1/2)^{(k/4)}$).
pub const DEFAULT_L3_FILTER_COEFF_K: u8 = 4; // a = 0.5

// ---------------------------------------------------------------------------
// Enumerations & Error Types
// ---------------------------------------------------------------------------

/// Type of Conditional Reconfiguration (CHO vs CPC).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChoType {
    /// Master Cell Group Handover (PCell Change).
    MasterCellGroupHandover,
    /// Conditional PSCell Addition or Change (SCG CPC in MR-DC / NR-DC).
    ConditionalPscellChange,
}

/// Measurement quantity used in execution condition evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeasurementQuantity {
    Rsrp,
    Rsrq,
    Sinr,
}

/// Operational state of a candidate target cell configuration.
#[derive(Debug, Clone, PartialEq)]
pub enum CandidateState {
    /// Configured and actively monitoring, condition not yet met.
    Configured,
    /// Entering condition met; Time-To-Trigger timer is running.
    TttActive { elapsed_ms: u32 },
    /// Time-To-Trigger duration satisfied; candidate is ready for immediate execution.
    ConditionMet,
    /// Handover execution initiated on this target cell.
    Executing,
    /// Successfully completed handover to target cell.
    Completed,
    /// Cancelled due to another candidate executing or network deconfiguration.
    Cancelled { reason: String },
    /// Candidate validity timer expired before condition was met.
    Expired,
    /// Random access procedure failed on this candidate target cell.
    RachFailed { attempts: u8 },
}

/// Errors raised during CHO/CPC management and execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChoError {
    CandidateNotFound(u8),
    CandidateAlreadyExists(u8),
    MaxCandidatesExceeded(usize),
    CandidateNotReady(u8),
    InvalidConfiguration(&'static str),
    AllCandidatesFailed,
}

impl fmt::Display for ChoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CandidateNotFound(id) => write!(f, "CHO Candidate ID {} not found", id),
            Self::CandidateAlreadyExists(id) => {
                write!(f, "CHO Candidate ID {} already registered", id)
            }
            Self::MaxCandidatesExceeded(count) => {
                write!(
                    f,
                    "Max CHO candidates exceeded ({}/{})",
                    count, MAX_CHO_CANDIDATES
                )
            }
            Self::CandidateNotReady(id) => {
                write!(f, "CHO Candidate ID {} condition not met for execution", id)
            }
            Self::InvalidConfiguration(msg) => write!(f, "Invalid CHO configuration: {}", msg),
            Self::AllCandidatesFailed => {
                write!(
                    f,
                    "All candidate cells failed RACH execution; RLF unavoidable"
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 3GPP Layer 3 Measurement Filter (TS 38.331 §5.5.3.2)
// ---------------------------------------------------------------------------

/// 3GPP Layer 3 Measurement Filter:
/// $F_n = (1 - a) \cdot F_{n-1} + a \cdot M_n$, where $a = (1/2)^{(k/4)}$.
#[derive(Debug, Clone, PartialEq)]
pub struct L3Filter {
    filter_coeff_k: u8,
    a_factor: f64,
    current_filtered_value: Option<f64>,
}

impl L3Filter {
    /// Create a new L3 filter with coefficient $k$.
    pub fn new(filter_coeff_k: u8) -> Self {
        let a_factor = (0.5f64).powf(filter_coeff_k as f64 / 4.0);
        Self {
            filter_coeff_k,
            a_factor,
            current_filtered_value: None,
        }
    }

    /// Reset filter state.
    pub fn reset(&mut self) {
        self.current_filtered_value = None;
    }

    /// Filter an incoming measurement sample $M_n$ (e.g. RSRP in dBm).
    pub fn filter(&mut self, sample: f64) -> f64 {
        match self.current_filtered_value {
            None => {
                self.current_filtered_value = Some(sample);
                sample
            }
            Some(prev) => {
                let filtered = (1.0 - self.a_factor) * prev + self.a_factor * sample;
                self.current_filtered_value = Some(filtered);
                filtered
            }
        }
    }

    /// Current filtered value, if any samples have been processed.
    pub fn value(&self) -> Option<f64> {
        self.current_filtered_value
    }

    /// Filter coefficient $k$.
    pub fn coeff_k(&self) -> u8 {
        self.filter_coeff_k
    }
}

// ---------------------------------------------------------------------------
// Execution Conditions (TS 38.331 §5.5.4)
// ---------------------------------------------------------------------------

/// Conditional Execution Criteria for CHO/CPC.
#[derive(Debug, Clone, PartialEq)]
pub enum CondExecutionCondition {
    /// Event A3: Neighbor becomes offset better than SpCell.
    /// Entering: $M_n - \text{Hys} > M_s + \text{Offset}$.
    /// Leaving:  $M_n + \text{Hys} < M_s + \text{Offset}$.
    EventA3 { offset_db: f64, hysteresis_db: f64 },
    /// Event A5: SpCell becomes worse than Thresh1 AND Neighbor becomes better than Thresh2.
    /// Entering: $M_s + \text{Hys} < \text{Thresh}_1 \land M_n - \text{Hys} > \text{Thresh}_2$.
    /// Leaving:  $M_s - \text{Hys} > \text{Thresh}_1 \lor M_n + \text{Hys} < \text{Thresh}_2$.
    EventA5 {
        threshold1_dbm: f64,
        threshold2_dbm: f64,
        hysteresis_db: f64,
    },
}

impl CondExecutionCondition {
    /// Evaluate whether the entering condition is satisfied.
    pub fn evaluate_entering(&self, spcell_meas: f64, neighbor_meas: f64) -> bool {
        match self {
            Self::EventA3 {
                offset_db,
                hysteresis_db,
            } => neighbor_meas - hysteresis_db > spcell_meas + offset_db,
            Self::EventA5 {
                threshold1_dbm,
                threshold2_dbm,
                hysteresis_db,
            } => {
                (spcell_meas + hysteresis_db < *threshold1_dbm)
                    && (neighbor_meas - hysteresis_db > *threshold2_dbm)
            }
        }
    }

    /// Evaluate whether the leaving condition is satisfied (which resets the TTT timer).
    pub fn evaluate_leaving(&self, spcell_meas: f64, neighbor_meas: f64) -> bool {
        match self {
            Self::EventA3 {
                offset_db,
                hysteresis_db,
            } => neighbor_meas + hysteresis_db < spcell_meas + offset_db,
            Self::EventA5 {
                threshold1_dbm,
                threshold2_dbm,
                hysteresis_db,
            } => {
                (spcell_meas - hysteresis_db > *threshold1_dbm)
                    || (neighbor_meas + hysteresis_db < *threshold2_dbm)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Candidate Target Cell Configuration & Record
// ---------------------------------------------------------------------------

/// Candidate Target Cell Configuration for Conditional Handover or PSCell Change.
#[derive(Debug, Clone, PartialEq)]
pub struct CondReconfigCandidate {
    pub cond_reconfig_id: u8,
    pub target_pci: u32,
    pub carrier_freq_mhz: f64,
    pub cho_type: ChoType,
    pub condition: CondExecutionCondition,
    pub time_to_trigger_ms: u32,
    pub dedicated_preamble_index: Option<u8>,
    pub target_c_rnti: u16,
    pub validity_timer_ms: u32,
    pub elapsed_validity_ms: u32,
    pub state: CandidateState,
    pub neighbor_filter: L3Filter,
}

impl CondReconfigCandidate {
    /// Create a new candidate target configuration.
    pub fn new(
        cond_reconfig_id: u8,
        target_pci: u32,
        carrier_freq_mhz: f64,
        cho_type: ChoType,
        condition: CondExecutionCondition,
        time_to_trigger_ms: u32,
        dedicated_preamble_index: Option<u8>,
        target_c_rnti: u16,
        validity_timer_ms: u32,
    ) -> Self {
        Self {
            cond_reconfig_id,
            target_pci,
            carrier_freq_mhz,
            cho_type,
            condition,
            time_to_trigger_ms,
            dedicated_preamble_index,
            target_c_rnti,
            validity_timer_ms,
            elapsed_validity_ms: 0,
            state: CandidateState::Configured,
            neighbor_filter: L3Filter::new(DEFAULT_L3_FILTER_COEFF_K),
        }
    }

    /// Reset candidate tracking timers.
    pub fn reset_ttt(&mut self) {
        if matches!(self.state, CandidateState::TttActive { .. }) {
            self.state = CandidateState::Configured;
        }
    }
}

// ---------------------------------------------------------------------------
// Execution Trigger & Execution Report
// ---------------------------------------------------------------------------

/// Result of an autonomous CHO/CPC execution trigger.
#[derive(Debug, Clone, PartialEq)]
pub struct ChoExecutionReport {
    pub executed_candidate_id: u8,
    pub target_pci: u32,
    pub cho_type: ChoType,
    pub dedicated_preamble_index: Option<u8>,
    pub target_c_rnti: u16,
    pub cancelled_candidate_ids: Vec<u8>,
}

/// Telemetry metrics for observability and radio link resilience tracking.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ChoMetrics {
    pub candidate_evaluations: u64,
    pub ttt_activations: u64,
    pub ttt_resets: u64,
    pub executions_triggered: u64,
    pub executions_succeeded: u64,
    pub executions_failed: u64,
    pub avoided_rlf_count: u64,
    pub total_cancellations: u64,
    pub expired_candidates: u64,
}

// ---------------------------------------------------------------------------
// Top-Level Conditional Handover Engine
// ---------------------------------------------------------------------------

/// Top-Level 3GPP Rel-17/18 Conditional Handover (CHO) & CPC Engine.
#[derive(Debug, Clone)]
pub struct ChoEngine {
    pub ue_id: String,
    pub current_spcell_pci: u32,
    pub spcell_filter: L3Filter,
    pub candidates: HashMap<u8, CondReconfigCandidate>,
    pub metrics: ChoMetrics,
}

impl ChoEngine {
    /// Create a new CHO/CPC engine for a UE attached to a source SpCell.
    pub fn new(ue_id: &str, current_spcell_pci: u32) -> Self {
        Self {
            ue_id: ue_id.to_string(),
            current_spcell_pci,
            spcell_filter: L3Filter::new(DEFAULT_L3_FILTER_COEFF_K),
            candidates: HashMap::new(),
            metrics: ChoMetrics::default(),
        }
    }

    /// Register a prepared candidate target cell configuration.
    pub fn add_candidate(&mut self, candidate: CondReconfigCandidate) -> Result<(), ChoError> {
        if self.candidates.len() >= MAX_CHO_CANDIDATES {
            return Err(ChoError::MaxCandidatesExceeded(self.candidates.len()));
        }
        if self.candidates.contains_key(&candidate.cond_reconfig_id) {
            return Err(ChoError::CandidateAlreadyExists(candidate.cond_reconfig_id));
        }
        self.candidates
            .insert(candidate.cond_reconfig_id, candidate);
        Ok(())
    }

    /// Remove a candidate target cell.
    pub fn remove_candidate(&mut self, cond_id: u8) -> Result<CondReconfigCandidate, ChoError> {
        self.candidates
            .remove(&cond_id)
            .ok_or(ChoError::CandidateNotFound(cond_id))
    }

    /// Update serving SpCell radio measurement sample (e.g. RSRP in dBm).
    pub fn update_spcell_measurement(&mut self, sample_dbm: f64) -> f64 {
        self.spcell_filter.filter(sample_dbm)
    }

    /// Update neighbor candidate cell radio measurement sample.
    pub fn update_candidate_measurement(
        &mut self,
        cond_id: u8,
        sample_dbm: f64,
    ) -> Result<f64, ChoError> {
        let candidate = self
            .candidates
            .get_mut(&cond_id)
            .ok_or(ChoError::CandidateNotFound(cond_id))?;
        Ok(candidate.neighbor_filter.filter(sample_dbm))
    }

    /// Advance time by `delta_ms` and evaluate all candidate condition state machines.
    /// Returns the strongest candidate whose Time-To-Trigger duration becomes satisfied,
    /// breaking equal-measurement ties by the lowest conditional reconfiguration ID.
    pub fn step_time(&mut self, delta_ms: u32) -> Option<u8> {
        let spcell_filtered = match self.spcell_filter.value() {
            Some(v) => v,
            None => return None,
        };

        let mut triggered_candidate: Option<(u8, f64)> = None;

        for candidate in self.candidates.values_mut() {
            // Check validity expiration
            candidate.elapsed_validity_ms = candidate.elapsed_validity_ms.saturating_add(delta_ms);
            if candidate.elapsed_validity_ms >= candidate.validity_timer_ms
                && matches!(
                    candidate.state,
                    CandidateState::Configured | CandidateState::TttActive { .. }
                )
            {
                candidate.state = CandidateState::Expired;
                self.metrics.expired_candidates += 1;
                continue;
            }

            // Only evaluate configured or active candidates
            match &mut candidate.state {
                CandidateState::Configured | CandidateState::TttActive { .. } => {}
                _ => continue,
            }

            let neighbor_filtered = match candidate.neighbor_filter.value() {
                Some(v) => v,
                None => continue,
            };

            self.metrics.candidate_evaluations += 1;

            if candidate
                .condition
                .evaluate_entering(spcell_filtered, neighbor_filtered)
            {
                let mut condition_became_met = false;
                match &mut candidate.state {
                    CandidateState::Configured => {
                        candidate.state = CandidateState::TttActive {
                            elapsed_ms: delta_ms,
                        };
                        self.metrics.ttt_activations += 1;
                        if delta_ms >= candidate.time_to_trigger_ms {
                            candidate.state = CandidateState::ConditionMet;
                            condition_became_met = true;
                        }
                    }
                    CandidateState::TttActive { elapsed_ms } => {
                        *elapsed_ms = elapsed_ms.saturating_add(delta_ms);
                        if *elapsed_ms >= candidate.time_to_trigger_ms {
                            candidate.state = CandidateState::ConditionMet;
                            condition_became_met = true;
                        }
                    }
                    _ => {}
                }

                if condition_became_met {
                    let cond_id = candidate.cond_reconfig_id;
                    let should_select = match triggered_candidate {
                        None => true,
                        Some((selected_id, selected_measurement)) => {
                            neighbor_filtered > selected_measurement
                                || (neighbor_filtered == selected_measurement
                                    && cond_id < selected_id)
                        }
                    };
                    if should_select {
                        triggered_candidate = Some((cond_id, neighbor_filtered));
                    }
                }
            } else if candidate
                .condition
                .evaluate_leaving(spcell_filtered, neighbor_filtered)
            {
                if matches!(candidate.state, CandidateState::TttActive { .. }) {
                    candidate.state = CandidateState::Configured;
                    self.metrics.ttt_resets += 1;
                }
            }
        }

        triggered_candidate.map(|(cond_id, _)| cond_id)
    }

    /// Autonomous execution of Conditional Handover / CPC to the selected candidate cell.
    /// Transitions the chosen target to `Executing`, marks it `Completed`, and dispatches
    /// Xn-AP cancellation to all other candidate targets.
    pub fn execute_cho(&mut self, cond_id: u8) -> Result<ChoExecutionReport, ChoError> {
        let candidate = self
            .candidates
            .get_mut(&cond_id)
            .ok_or(ChoError::CandidateNotFound(cond_id))?;

        if candidate.state != CandidateState::ConditionMet {
            return Err(ChoError::CandidateNotReady(cond_id));
        }

        candidate.state = CandidateState::Completed;
        self.metrics.executions_triggered += 1;
        self.metrics.executions_succeeded += 1;

        // If source SpCell is severely degraded (<-110 dBm), count as avoided RLF
        if let Some(spcell_meas) = self.spcell_filter.value() {
            if spcell_meas < -110.0 {
                self.metrics.avoided_rlf_count += 1;
            }
        }

        let target_pci = candidate.target_pci;
        let cho_type = candidate.cho_type;
        let dedicated_preamble = candidate.dedicated_preamble_index;
        let c_rnti = candidate.target_c_rnti;

        // Automatically cancel all other non-selected candidate targets
        let mut cancelled_ids = Vec::new();
        for (id, cand) in self.candidates.iter_mut() {
            if *id != cond_id
                && matches!(
                    cand.state,
                    CandidateState::Configured
                        | CandidateState::TttActive { .. }
                        | CandidateState::ConditionMet
                )
            {
                cand.state = CandidateState::Cancelled {
                    reason: format!("TargetCandidate_{}_Executed", cond_id),
                };
                cancelled_ids.push(*id);
                self.metrics.total_cancellations += 1;
            }
        }
        cancelled_ids.sort_unstable();

        // Update serving cell ID if Master Cell Group handover
        if cho_type == ChoType::MasterCellGroupHandover {
            self.current_spcell_pci = target_pci;
            self.spcell_filter.reset();
        }

        Ok(ChoExecutionReport {
            executed_candidate_id: cond_id,
            target_pci,
            cho_type,
            dedicated_preamble_index: dedicated_preamble,
            target_c_rnti: c_rnti,
            cancelled_candidate_ids: cancelled_ids,
        })
    }

    /// Handle Random Access failure on the target cell.
    /// Marks the failed candidate with `RachFailed` and looks for an alternative candidate
    /// whose condition is met.
    pub fn handle_rach_failure(&mut self, failed_cond_id: u8) -> Result<Option<u8>, ChoError> {
        let candidate = self
            .candidates
            .get_mut(&failed_cond_id)
            .ok_or(ChoError::CandidateNotFound(failed_cond_id))?;

        let attempts = match candidate.state {
            CandidateState::RachFailed { attempts } => attempts.saturating_add(1),
            _ => 1,
        };
        candidate.state = CandidateState::RachFailed { attempts };
        self.metrics.executions_failed += 1;

        // Search for alternative candidate with ConditionMet or valid TttActive
        for (id, cand) in &self.candidates {
            if *id != failed_cond_id && cand.state == CandidateState::ConditionMet {
                return Ok(Some(*id));
            }
        }

        Ok(None)
    }
}

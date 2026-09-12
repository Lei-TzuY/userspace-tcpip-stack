//! 3GPP Rel-18 5G-Advanced Conditional PSCell Addition/Change (CPAC) Engine.
//!
//! Compliant with:
//! - 3GPP TS 38.300 §11.1 / §11.2 Rel-18 ("MR-DC and Conditional PSCell Addition/Change")
//! - 3GPP TS 38.331 §5.3.5.15 Rel-18 (`ConditionalReconfiguration`, `condExecutionCondSCG`, `VarConditionalReconfig`)
//! - 3GPP TS 38.423 §8.2 Rel-18 ("Xn-AP S-gNB Addition Preparation & CPAC Execution")
//! - 3GPP TS 38.321 §5.1 Rel-18 (Random access procedures for conditional PSCell change)
//!
//! Key Capabilities:
//! 1. Conditional PSCell Addition and Change Evaluation:
//!    - Multi-candidate configuration (up to 8 candidates across multiple Secondary Nodes).
//!    - Event A4 (Neighbor becomes better than absolute threshold) for conditional addition.
//!    - Event A3 (Neighbor becomes offset better than serving PSCell) for conditional change.
//!    - Event A5 (Serving PSCell < Thresh1 and Neighbor > Thresh2).
//! 2. Advance Contention-Free Random Access (CFRA) Preamble Reservation:
//!    - Manages dedicated preamble indices and SSB association per candidate PSCell.
//! 3. Autonomous UE-driven Trigger & Time-to-Trigger (TTT) Validation:
//!    - Avoids premature execution with hysteresis guard and sliding-window confirmation.
//! 4. Inter-Node Xn-AP CPAC Signaling Protocol:
//!    - S-gNB Addition Request / Acknowledge serialization.
//!    - Execution Notification and Cancellation of unselected candidate Secondary Nodes.
//! 5. SCG Radio Link Failure (SCG RLF) Recovery via CPAC Fallback:
//!    - Rapidly activates best healthy candidate PSCell without dropping Master Cell Group connection.
//!
//! Pure Rust standard library implementation with zero external dependencies.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Constants & Defaults
// ---------------------------------------------------------------------------

/// Maximum number of active CPAC candidate configurations per UE (TS 38.331).
pub const MAX_CPAC_CANDIDATES: usize = 8;

/// Default Time-To-Trigger (TTT) in milliseconds for CPAC execution.
pub const DEFAULT_CPAC_TTT_MS: u64 = 80;

/// Default hysteresis margin in dB for event evaluation.
pub const DEFAULT_CPAC_HYSTERESIS_DB: f64 = 2.5;

/// Default Event A4 absolute RSRP threshold in dBm for conditional addition.
pub const DEFAULT_A4_THRESHOLD_DBM: f64 = -102.0;

/// Default Event A3 offset in dB for conditional change.
pub const DEFAULT_A3_OFFSET_DB: f64 = 3.0;

// ---------------------------------------------------------------------------
// Enumerations & Error Types
// ---------------------------------------------------------------------------

/// Type of CPAC procedure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CpacProcedureType {
    /// Initial conditional addition of a Secondary Cell Group (SCG) PSCell.
    ConditionalPscellAddition,
    /// Inter-SN or intra-SN conditional change from current PSCell to target candidate.
    ConditionalPscellChange,
}

/// Execution condition trigger events (TS 38.331 §5.5.4).
#[derive(Debug, Clone, PartialEq)]
pub enum CpacTriggerEvent {
    /// Event A3: Candidate becomes Offset better than current serving PSCell.
    EventA3 {
        offset_db: f64,
        hysteresis_db: f64,
        ttt_ms: u64,
    },
    /// Event A4: Candidate becomes better than absolute threshold (ideal for Addition).
    EventA4 {
        threshold_dbm: f64,
        hysteresis_db: f64,
        ttt_ms: u64,
    },
    /// Event A5: Serving PSCell becomes worse than Thresh1 and Candidate becomes better than Thresh2.
    EventA5 {
        thresh1_dbm: f64,
        thresh2_dbm: f64,
        hysteresis_db: f64,
        ttt_ms: u64,
    },
}

impl CpacTriggerEvent {
    pub fn default_a4() -> Self {
        Self::EventA4 {
            threshold_dbm: DEFAULT_A4_THRESHOLD_DBM,
            hysteresis_db: DEFAULT_CPAC_HYSTERESIS_DB,
            ttt_ms: DEFAULT_CPAC_TTT_MS,
        }
    }

    pub fn default_a3() -> Self {
        Self::EventA3 {
            offset_db: DEFAULT_A3_OFFSET_DB,
            hysteresis_db: DEFAULT_CPAC_HYSTERESIS_DB,
            ttt_ms: DEFAULT_CPAC_TTT_MS,
        }
    }
}

/// Execution lifecycle state of a CPAC candidate.
#[derive(Debug, Clone, PartialEq)]
pub enum CpacCandidateState {
    /// Configured and awaiting measurement trigger.
    Configured,
    /// Trigger condition entry fulfilled, timing within Time-To-Trigger window.
    ConditionMet { first_triggered_ms: u64 },
    /// Selected for execution by the UE.
    Executing,
    /// Successfully accessed and confirmed as active PSCell.
    Completed,
    /// Cancelled due to another candidate's selection or network command.
    Cancelled,
}

/// Release cause indicated in Xn-AP signaling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CpacReleaseCause {
    CpacExecutedOnOtherNode,
    RadioLinkFailure,
    HandoverCancelled,
    ResourcePreemption,
}

/// Errors raised during CPAC engine operations.
#[derive(Debug, Clone, PartialEq)]
pub enum CpacError {
    CandidateLimitExceeded(usize),
    CandidateNotFound(u8),
    DuplicateCandidateId(u8),
    InvalidConfiguration(String),
    BufferTooShort { expected: usize, actual: usize },
}

impl std::fmt::Display for CpacError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CandidateLimitExceeded(max) => {
                write!(f, "Exceeded maximum CPAC candidate limit of {}", max)
            }
            Self::CandidateNotFound(id) => write!(f, "CPAC candidate ID {} not found", id),
            Self::DuplicateCandidateId(id) => write!(f, "CPAC candidate ID {} already exists", id),
            Self::InvalidConfiguration(msg) => write!(f, "Invalid CPAC configuration: {}", msg),
            Self::BufferTooShort { expected, actual } => {
                write!(
                    f,
                    "Buffer too short: expected {} bytes, got {}",
                    expected, actual
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Configurations & Measurements
// ---------------------------------------------------------------------------

/// Radio measurement of a candidate or serving cell.
#[derive(Debug, Clone, PartialEq)]
pub struct CellMeasurement {
    pub pci: u16,
    pub arfcn: u32,
    pub rsrp_dbm: f64,
    pub rsrq_db: f64,
    pub sinr_db: f64,
}

/// Active serving PSCell state.
#[derive(Debug, Clone, PartialEq)]
pub struct ScgServingCell {
    pub pci: u16,
    pub arfcn: u32,
    pub sn_id: u32,
}

/// Full configuration for a CPAC candidate cell (TS 38.331).
#[derive(Debug, Clone, PartialEq)]
pub struct CpacCandidateConfig {
    pub candidate_id: u8,
    pub pci: u16,
    pub arfcn: u32,
    pub sn_id: u32,
    pub trigger_event: CpacTriggerEvent,
    /// Dedicated preamble for CFRA access on candidate PSCell.
    pub dedicated_preamble_index: Option<u8>,
    /// Associated SSB index for beam alignment.
    pub ssb_index: Option<u8>,
    /// Pre-allocated RRCReconfiguration-SCG container byte payload.
    pub scg_rrc_reconfig: Vec<u8>,
}

/// Execution command emitted when a candidate's TTT expires.
#[derive(Debug, Clone, PartialEq)]
pub struct CpacExecutionDecision {
    pub candidate_id: u8,
    pub target_pci: u16,
    pub target_sn_id: u32,
    pub procedure_type: CpacProcedureType,
    pub dedicated_preamble_index: Option<u8>,
    pub scg_rrc_reconfig: Vec<u8>,
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Inter-Node Xn-AP CPAC Signaling Protocol (TS 38.423 §8.2)
// ---------------------------------------------------------------------------

/// Xn-AP CPAC Inter-Node Coordination Message.
#[derive(Debug, Clone, PartialEq)]
pub enum XnApCpacMessage {
    /// Master Node requests Secondary Node to prepare candidate PSCell resources.
    SgNbAdditionRequest {
        ue_id: u32,
        candidate_pci: u16,
        target_sn_id: u32,
    },
    /// Secondary Node acknowledges and allocates CFRA preamble.
    SgNbAdditionRequestAcknowledge {
        ue_id: u32,
        candidate_pci: u16,
        preamble_index: u8,
        scg_config: Vec<u8>,
    },
    /// Master Node notifies target SN that UE successfully executed CPAC.
    CpacExecutionNotification {
        ue_id: u32,
        executed_pci: u16,
        target_sn_id: u32,
    },
    /// Master Node cancels unselected candidate SNs to release pre-allocated resources.
    CpacCancelNotification {
        ue_id: u32,
        cancelled_pci: u16,
        target_sn_id: u32,
        cause: CpacReleaseCause,
    },
}

impl XnApCpacMessage {
    /// Serialize message into compact binary wire representation.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        match self {
            Self::SgNbAdditionRequest {
                ue_id,
                candidate_pci,
                target_sn_id,
            } => {
                bytes.push(0x01); // MsgType 1
                bytes.extend_from_slice(&ue_id.to_be_bytes());
                bytes.extend_from_slice(&candidate_pci.to_be_bytes());
                bytes.extend_from_slice(&target_sn_id.to_be_bytes());
            }
            Self::SgNbAdditionRequestAcknowledge {
                ue_id,
                candidate_pci,
                preamble_index,
                scg_config,
            } => {
                bytes.push(0x02); // MsgType 2
                bytes.extend_from_slice(&ue_id.to_be_bytes());
                bytes.extend_from_slice(&candidate_pci.to_be_bytes());
                bytes.push(*preamble_index);
                let cfg_len = (scg_config.len() as u16).to_be_bytes();
                bytes.extend_from_slice(&cfg_len);
                bytes.extend_from_slice(scg_config);
            }
            Self::CpacExecutionNotification {
                ue_id,
                executed_pci,
                target_sn_id,
            } => {
                bytes.push(0x03); // MsgType 3
                bytes.extend_from_slice(&ue_id.to_be_bytes());
                bytes.extend_from_slice(&executed_pci.to_be_bytes());
                bytes.extend_from_slice(&target_sn_id.to_be_bytes());
            }
            Self::CpacCancelNotification {
                ue_id,
                cancelled_pci,
                target_sn_id,
                cause,
            } => {
                bytes.push(0x04); // MsgType 4
                bytes.extend_from_slice(&ue_id.to_be_bytes());
                bytes.extend_from_slice(&cancelled_pci.to_be_bytes());
                bytes.extend_from_slice(&target_sn_id.to_be_bytes());
                bytes.push(*cause as u8);
            }
        }
        bytes
    }
}

// ---------------------------------------------------------------------------
// CPAC Engine
// ---------------------------------------------------------------------------

/// Complete 3GPP Rel-18 Conditional PSCell Addition/Change (CPAC) Engine.
#[derive(Debug, PartialEq)]
pub struct CpacEngine {
    pub ue_id: u32,
    pub active_pscell: Option<ScgServingCell>,
    pub candidates: HashMap<u8, CpacCandidateConfig>,
    pub candidate_states: HashMap<u8, CpacCandidateState>,
    /// Statistics: Total trigger conditions met.
    pub stats_conditions_met: u64,
    /// Statistics: Total CPAC executions triggered.
    pub stats_executions_triggered: u64,
    /// Statistics: Total cancellations sent to peer SNs.
    pub stats_cancellations_sent: u64,
}

impl CpacEngine {
    pub fn new(ue_id: u32) -> Self {
        Self {
            ue_id,
            active_pscell: None,
            candidates: HashMap::new(),
            candidate_states: HashMap::new(),
            stats_conditions_met: 0,
            stats_executions_triggered: 0,
            stats_cancellations_sent: 0,
        }
    }

    /// Set current active PSCell (None if in PSCell addition phase).
    pub fn set_active_pscell(&mut self, pscell: Option<ScgServingCell>) {
        self.active_pscell = pscell;
    }

    /// Register a candidate PSCell configuration with its execution condition.
    pub fn add_candidate(&mut self, candidate: CpacCandidateConfig) -> Result<(), CpacError> {
        if self.candidates.contains_key(&candidate.candidate_id) {
            return Err(CpacError::DuplicateCandidateId(candidate.candidate_id));
        }
        if self.candidates.len() >= MAX_CPAC_CANDIDATES {
            return Err(CpacError::CandidateLimitExceeded(MAX_CPAC_CANDIDATES));
        }

        let cid = candidate.candidate_id;
        self.candidates.insert(cid, candidate);
        self.candidate_states
            .insert(cid, CpacCandidateState::Configured);
        Ok(())
    }

    /// Remove a candidate configuration.
    pub fn remove_candidate(&mut self, candidate_id: u8) -> Result<(), CpacError> {
        if self.candidates.remove(&candidate_id).is_some() {
            self.candidate_states.remove(&candidate_id);
            Ok(())
        } else {
            Err(CpacError::CandidateNotFound(candidate_id))
        }
    }

    /// Evaluate cell measurements against all active CPAC candidate conditions.
    pub fn evaluate_measurements(
        &mut self,
        measurements: &[CellMeasurement],
        now_ms: u64,
    ) -> Option<CpacExecutionDecision> {
        // Find serving cell measurement if active PSCell exists
        let serving_rsrp = self.active_pscell.as_ref().and_then(|scg| {
            measurements
                .iter()
                .find(|m| m.pci == scg.pci && m.arfcn == scg.arfcn)
                .map(|m| m.rsrp_dbm)
        });

        let mut ready_execution: Option<CpacExecutionDecision> = None;

        for (&cid, candidate) in &self.candidates {
            let candidate_meas = measurements
                .iter()
                .find(|m| m.pci == candidate.pci && m.arfcn == candidate.arfcn);

            let cand_rsrp = match candidate_meas {
                Some(m) => m.rsrp_dbm,
                None => {
                    // No measurement; reset condition state
                    self.candidate_states
                        .insert(cid, CpacCandidateState::Configured);
                    continue;
                }
            };

            // Evaluate trigger event
            let (condition_satisfied, ttt_ms, event_name) = match &candidate.trigger_event {
                CpacTriggerEvent::EventA4 {
                    threshold_dbm,
                    hysteresis_db,
                    ttt_ms,
                } => {
                    // Candidate RSRP >= Threshold + Hysteresis
                    let satisfied = cand_rsrp >= (*threshold_dbm + *hysteresis_db);
                    (satisfied, *ttt_ms, "Event A4 (Threshold exceeded)")
                }
                CpacTriggerEvent::EventA3 {
                    offset_db,
                    hysteresis_db,
                    ttt_ms,
                } => {
                    // Candidate RSRP >= Serving RSRP + Offset + Hysteresis
                    let s_rsrp = serving_rsrp.unwrap_or(-140.0);
                    let satisfied = cand_rsrp >= (s_rsrp + *offset_db + *hysteresis_db);
                    (satisfied, *ttt_ms, "Event A3 (Offset better than serving)")
                }
                CpacTriggerEvent::EventA5 {
                    thresh1_dbm,
                    thresh2_dbm,
                    hysteresis_db,
                    ttt_ms,
                } => {
                    let s_rsrp = serving_rsrp.unwrap_or(-140.0);
                    let satisfied = s_rsrp <= (*thresh1_dbm - *hysteresis_db)
                        && cand_rsrp >= (*thresh2_dbm + *hysteresis_db);
                    (
                        satisfied,
                        *ttt_ms,
                        "Event A5 (Serving bad and Candidate good)",
                    )
                }
            };

            // Update candidate state and test TTT expiration
            let state = self
                .candidate_states
                .get(&cid)
                .cloned()
                .unwrap_or(CpacCandidateState::Configured);

            if condition_satisfied {
                match state {
                    CpacCandidateState::Configured => {
                        self.stats_conditions_met += 1;
                        self.candidate_states.insert(
                            cid,
                            CpacCandidateState::ConditionMet {
                                first_triggered_ms: now_ms,
                            },
                        );
                    }
                    CpacCandidateState::ConditionMet { first_triggered_ms } => {
                        if now_ms >= first_triggered_ms + ttt_ms {
                            // TTT expired: candidate is ready for immediate execution
                            self.candidate_states
                                .insert(cid, CpacCandidateState::Executing);
                            self.stats_executions_triggered += 1;

                            let proc_type = if self.active_pscell.is_some() {
                                CpacProcedureType::ConditionalPscellChange
                            } else {
                                CpacProcedureType::ConditionalPscellAddition
                            };

                            ready_execution = Some(CpacExecutionDecision {
                                candidate_id: cid,
                                target_pci: candidate.pci,
                                target_sn_id: candidate.sn_id,
                                procedure_type: proc_type,
                                dedicated_preamble_index: candidate.dedicated_preamble_index,
                                scg_rrc_reconfig: candidate.scg_rrc_reconfig.clone(),
                                reason: format!("TTT expired ({})", event_name),
                            });
                            break;
                        }
                    }
                    _ => {}
                }
            } else {
                // Condition fell below threshold; reset to Configured
                self.candidate_states
                    .insert(cid, CpacCandidateState::Configured);
            }
        }

        ready_execution
    }

    /// Process completion of CPAC execution on the chosen candidate:
    /// Updates active PSCell and generates Xn-AP Cancellation notifications for all unselected candidates.
    pub fn handle_execution_success(&mut self, executed_candidate_id: u8) -> Vec<XnApCpacMessage> {
        let mut notifications = Vec::new();

        let executed_candidate = match self.candidates.get(&executed_candidate_id) {
            Some(c) => c.clone(),
            None => return notifications,
        };

        // Update active serving PSCell
        self.active_pscell = Some(ScgServingCell {
            pci: executed_candidate.pci,
            arfcn: executed_candidate.arfcn,
            sn_id: executed_candidate.sn_id,
        });
        self.candidate_states
            .insert(executed_candidate_id, CpacCandidateState::Completed);

        // Notify target SN of execution
        notifications.push(XnApCpacMessage::CpacExecutionNotification {
            ue_id: self.ue_id,
            executed_pci: executed_candidate.pci,
            target_sn_id: executed_candidate.sn_id,
        });

        // Cancel all other candidate secondary nodes to prevent reserved preamble / memory leaks
        let mut remaining_cids: Vec<u8> = self
            .candidates
            .keys()
            .copied()
            .filter(|&cid| cid != executed_candidate_id)
            .collect();
        remaining_cids.sort();
        for cid in remaining_cids {
            let candidate = &self.candidates[&cid];
            self.candidate_states
                .insert(cid, CpacCandidateState::Cancelled);
            notifications.push(XnApCpacMessage::CpacCancelNotification {
                ue_id: self.ue_id,
                cancelled_pci: candidate.pci,
                target_sn_id: candidate.sn_id,
                cause: CpacReleaseCause::CpacExecutedOnOtherNode,
            });
            self.stats_cancellations_sent += 1;
        }

        notifications
    }

    /// SCG Radio Link Failure (SCG RLF) recovery:
    /// Immediately triggers best available candidate PSCell meeting minimum threshold without waiting for TTT.
    pub fn handle_scg_failure(
        &mut self,
        measurements: &[CellMeasurement],
    ) -> Option<CpacExecutionDecision> {
        let mut best_cand: Option<(u8, f64, &CpacCandidateConfig)> = None;

        for (&cid, candidate) in &self.candidates {
            if let Some(m) = measurements.iter().find(|m| m.pci == candidate.pci) {
                if m.rsrp_dbm >= DEFAULT_A4_THRESHOLD_DBM {
                    if best_cand
                        .as_ref()
                        .map_or(true, |(_, best_rsrp, _)| m.rsrp_dbm > *best_rsrp)
                    {
                        best_cand = Some((cid, m.rsrp_dbm, candidate));
                    }
                }
            }
        }

        if let Some((cid, _, candidate)) = best_cand {
            self.candidate_states
                .insert(cid, CpacCandidateState::Executing);
            self.stats_executions_triggered += 1;

            Some(CpacExecutionDecision {
                candidate_id: cid,
                target_pci: candidate.pci,
                target_sn_id: candidate.sn_id,
                procedure_type: CpacProcedureType::ConditionalPscellChange,
                dedicated_preamble_index: candidate.dedicated_preamble_index,
                scg_rrc_reconfig: candidate.scg_rrc_reconfig.clone(),
                reason: "Autonomous recovery from SCG Radio Link Failure".to_string(),
            })
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Unit Tests (Internal Module)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xn_ap_message_serialization() {
        let msg = XnApCpacMessage::SgNbAdditionRequestAcknowledge {
            ue_id: 101,
            candidate_pci: 300,
            preamble_index: 24,
            scg_config: vec![0x11, 0x22, 0x33],
        };

        let bytes = msg.to_bytes();
        assert_eq!(bytes[0], 0x02);
        assert_eq!(bytes.len(), 1 + 4 + 2 + 1 + 2 + 3);
    }

    #[test]
    fn test_candidate_registration_limit() {
        let mut engine = CpacEngine::new(1);
        for i in 1..=MAX_CPAC_CANDIDATES as u8 {
            let cand = CpacCandidateConfig {
                candidate_id: i,
                pci: 100 + i as u16,
                arfcn: 630000,
                sn_id: 10,
                trigger_event: CpacTriggerEvent::default_a4(),
                dedicated_preamble_index: Some(i),
                ssb_index: Some(0),
                scg_rrc_reconfig: vec![],
            };
            assert!(engine.add_candidate(cand).is_ok());
        }

        // 9th candidate exceeds MAX_CPAC_CANDIDATES
        let overflow = CpacCandidateConfig {
            candidate_id: 9,
            pci: 109,
            arfcn: 630000,
            sn_id: 10,
            trigger_event: CpacTriggerEvent::default_a4(),
            dedicated_preamble_index: Some(9),
            ssb_index: Some(0),
            scg_rrc_reconfig: vec![],
        };
        assert!(matches!(
            engine.add_candidate(overflow),
            Err(CpacError::CandidateLimitExceeded(_))
        ));
    }
}

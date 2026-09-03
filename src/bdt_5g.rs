//! 3GPP TS 29.522 / TS 23.501 Section 5.8.4 / TS 29.512 Release 17 5G Background Data Transfer (BDT) Policy Negotiation Engine.
//!
//! Implements 5G SBA Nnef_BDTPNegotiation & Npcf_BDTPNegotiation services:
//! - Ingests external Application Function (AF) bulk data transfer requirements
//! - Evaluates off-peak network congestion windows and tariff discount models
//! - Generates multi-choice Candidate Transfer Policies (off-peak hours, bandwidth caps, rating groups)
//! - Commits selected policy to UDR/PCF with a globally unique 3GPP BDT Reference ID (bdt_ref_id)
//! - Enforces real-time time-window compliance and charging discount accounting

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// 5G BDT Enums & Data Structures (TS 29.522 / TS 29.512)
// ---------------------------------------------------------------------------

/// Universal Time Window specified in Unix epoch seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeWindow {
    pub start_time_epoch_s: u64,
    pub end_time_epoch_s: u64,
}

impl TimeWindow {
    pub fn is_within(&self, timestamp_s: u64) -> bool {
        timestamp_s >= self.start_time_epoch_s && timestamp_s <= self.end_time_epoch_s
    }

    pub fn duration_s(&self) -> u64 {
        if self.end_time_epoch_s >= self.start_time_epoch_s {
            self.end_time_epoch_s - self.start_time_epoch_s
        } else {
            0
        }
    }
}

/// AF Request for Background Data Transfer (TS 29.522 Section 4.4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BdtTransferRequest {
    pub af_id: String,
    pub volume_per_ue_bytes: u64,
    pub number_of_ues: u32,
    pub desired_window: TimeWindow,
    pub network_area_ta_list: Vec<String>,
}

/// Candidate Transfer Policy offered to the AF (TS 29.512 Section 5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BdtPolicyCandidate {
    pub bdt_policy_id: u32,
    pub time_window: TimeWindow,
    pub rating_group: u32,
    pub discount_percent: u8,
    pub max_bandwidth_bps: u64,
}

/// Negotiation Lifecycle State.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BdtNegotiationState {
    Proposed,
    Committed,
    Active,
    Completed,
    Rejected,
}

/// Active BDT Negotiation Session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BdtNegotiationSession {
    pub bdt_ref_id: String,
    pub af_id: String,
    pub volume_per_ue_bytes: u64,
    pub number_of_ues: u32,
    pub network_area_ta_list: Vec<String>,
    pub candidate_policies: Vec<BdtPolicyCandidate>,
    pub selected_policy: Option<BdtPolicyCandidate>,
    pub state: BdtNegotiationState,
    pub total_bytes_transferred: u64,
}

/// BDT Error Types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BdtError {
    SessionNotFound,
    PolicyNotFound { policy_id: u32 },
    InvalidTimeWindow,
    ZeroVolumeOrUes,
    SessionNotCommitted,
    OutsidePermittedTimeWindow { current: u64, start: u64, end: u64 },
    TransferVolumeQuotaExceeded { transferred: u64, max_allowed: u64 },
}

// ---------------------------------------------------------------------------
// Top-Level 5G BDT Engine
// ---------------------------------------------------------------------------

/// 5G Background Data Transfer (BDT) Policy Negotiation Engine.
pub struct BdtEngine {
    pub engine_id: String,
    pub sessions: HashMap<String, BdtNegotiationSession>,
    next_ref_counter: u64,
}

impl BdtEngine {
    /// Create a new 5G BDT engine instance.
    pub fn new(engine_id: &str) -> Self {
        BdtEngine {
            engine_id: engine_id.to_string(),
            sessions: HashMap::new(),
            next_ref_counter: 1001,
        }
    }

    /// Ingest an AF request and propose candidate transfer policies.
    pub fn propose_bdt_negotiation(
        &mut self,
        req: BdtTransferRequest,
    ) -> Result<(String, Vec<BdtPolicyCandidate>), BdtError> {
        if req.volume_per_ue_bytes == 0 || req.number_of_ues == 0 {
            return Err(BdtError::ZeroVolumeOrUes);
        }
        if req.desired_window.start_time_epoch_s >= req.desired_window.end_time_epoch_s {
            return Err(BdtError::InvalidTimeWindow);
        }

        let bdt_ref_id = format!("bdt-ref-{}-{}", self.engine_id, self.next_ref_counter);
        self.next_ref_counter += 1;

        // Generate 2 differentiated off-peak candidate policies:
        // Policy 1: Deep night window (01:00 - 05:00 relative offset) with 80% discount
        let w1_start = req.desired_window.start_time_epoch_s + 3600;
        let w1_end = w1_start + 14400; // 4 hours
        let policy1 = BdtPolicyCandidate {
            bdt_policy_id: 1,
            time_window: TimeWindow {
                start_time_epoch_s: w1_start.min(req.desired_window.end_time_epoch_s),
                end_time_epoch_s: w1_end.min(req.desired_window.end_time_epoch_s),
            },
            rating_group: 8001,
            discount_percent: 80,
            max_bandwidth_bps: 100_000_000, // 100 Mbps
        };

        // Policy 2: Early morning window (05:00 - 08:00 relative offset) with 50% discount
        let w2_start = w1_end;
        let w2_end = w2_start + 10800; // 3 hours
        let policy2 = BdtPolicyCandidate {
            bdt_policy_id: 2,
            time_window: TimeWindow {
                start_time_epoch_s: w2_start.min(req.desired_window.end_time_epoch_s),
                end_time_epoch_s: w2_end.min(req.desired_window.end_time_epoch_s),
            },
            rating_group: 8002,
            discount_percent: 50,
            max_bandwidth_bps: 50_000_000, // 50 Mbps
        };

        let candidates = vec![policy1, policy2];

        let session = BdtNegotiationSession {
            bdt_ref_id: bdt_ref_id.clone(),
            af_id: req.af_id,
            volume_per_ue_bytes: req.volume_per_ue_bytes,
            number_of_ues: req.number_of_ues,
            network_area_ta_list: req.network_area_ta_list,
            candidate_policies: candidates.clone(),
            selected_policy: None,
            state: BdtNegotiationState::Proposed,
            total_bytes_transferred: 0,
        };

        self.sessions.insert(bdt_ref_id.clone(), session);
        Ok((bdt_ref_id, candidates))
    }

    /// Commit the AF's selected policy candidate.
    pub fn commit_bdt_policy(
        &mut self,
        bdt_ref_id: &str,
        selected_policy_id: u32,
    ) -> Result<(), BdtError> {
        let sess = self
            .sessions
            .get_mut(bdt_ref_id)
            .ok_or(BdtError::SessionNotFound)?;

        let chosen = sess
            .candidate_policies
            .iter()
            .find(|p| p.bdt_policy_id == selected_policy_id)
            .cloned()
            .ok_or(BdtError::PolicyNotFound {
                policy_id: selected_policy_id,
            })?;

        sess.selected_policy = Some(chosen);
        sess.state = BdtNegotiationState::Committed;
        Ok(())
    }

    /// Reject proposed policies.
    pub fn reject_bdt_negotiation(&mut self, bdt_ref_id: &str) -> Result<(), BdtError> {
        let sess = self
            .sessions
            .get_mut(bdt_ref_id)
            .ok_or(BdtError::SessionNotFound)?;
        sess.state = BdtNegotiationState::Rejected;
        sess.selected_policy = None;
        Ok(())
    }

    /// Verify time window compliance and account transferred bytes for a UE data transfer.
    pub fn verify_and_account_traffic(
        &mut self,
        bdt_ref_id: &str,
        current_time_s: u64,
        bytes_to_transfer: u64,
    ) -> Result<u32, BdtError> {
        let sess = self
            .sessions
            .get_mut(bdt_ref_id)
            .ok_or(BdtError::SessionNotFound)?;

        if sess.state != BdtNegotiationState::Committed && sess.state != BdtNegotiationState::Active
        {
            return Err(BdtError::SessionNotCommitted);
        }

        let policy = sess
            .selected_policy
            .as_ref()
            .ok_or(BdtError::SessionNotCommitted)?;

        // 1. Time Window Check
        if !policy.time_window.is_within(current_time_s) {
            return Err(BdtError::OutsidePermittedTimeWindow {
                current: current_time_s,
                start: policy.time_window.start_time_epoch_s,
                end: policy.time_window.end_time_epoch_s,
            });
        }

        // 2. Volume Quota Check (volume_per_ue * number_of_ues)
        let max_allowed = sess.volume_per_ue_bytes * (sess.number_of_ues as u64);
        if sess.total_bytes_transferred + bytes_to_transfer > max_allowed {
            return Err(BdtError::TransferVolumeQuotaExceeded {
                transferred: sess.total_bytes_transferred + bytes_to_transfer,
                max_allowed,
            });
        }

        sess.state = BdtNegotiationState::Active;
        sess.total_bytes_transferred += bytes_to_transfer;

        Ok(policy.rating_group)
    }
}

//! 3GPP TS 32.291 / TS 32.255 5G Converged Charging Function (CHF) Engine.
//!
//! Implements 5G Core online/offline converged charging architecture:
//! - Nchf_ConvergedCharging Service (TS 32.291 Section 5.2):
//!   - Session-based charging lifecycle (Initial, Update, Termination requests)
//!   - Real-time rating, credit reservation, and Granted Quota Units (GQU) calculation
//!   - Used Quota Units (UQU) reconciliation and account debiting
//!   - Out-of-credit Final Unit Indication (FUI) handling (Terminate, Redirect, RestrictAccess)
//! - 5G Offline Charging Data Record (CDR) generation (TS 32.298 / TS 32.255)

use std::collections::HashMap;

use crate::ngap_5g::Snssai;

// ---------------------------------------------------------------------------
// Charging Data Structures & Enums (TS 32.291 Section 6)
// ---------------------------------------------------------------------------

/// Cause for reporting used quota units from SMF to CHF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportingReason {
    ThresholdReached,
    ValidityTimeExpired,
    FinalUnit,
    RatingConditionChange,
    SessionTermination,
}

/// Final Unit Action when subscriber runs out of credit (TS 32.291 Section 6.1.6.3.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinalUnitAction {
    Terminate,
    Redirect { redirect_server_url: String },
    RestrictAccess { max_bitrate_kbps: u32 },
}

/// Final Unit Indication instructing SMF/UPF on handling credit exhaustion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalUnitIndication {
    pub action: FinalUnitAction,
}

/// Granted Quota Units returned by CHF to SMF (TS 32.291 Section 6.1.6.2.14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantedQuotaUnit {
    pub total_volume_bytes: u64,
    pub uplink_volume_bytes: u64,
    pub downlink_volume_bytes: u64,
    pub validity_time_s: u32,
    pub quota_threshold_volume_bytes: Option<u64>,
}

/// Used Quota Units reported by SMF to CHF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsedQuotaUnit {
    pub rating_group: u32,
    pub total_volume_bytes: u64,
    pub uplink_volume_bytes: u64,
    pub downlink_volume_bytes: u64,
    pub reporting_reason: ReportingReason,
}

/// Operating state of a Converged Charging session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChargingSessionState {
    Active,
    FinalUnitReached,
    Terminated,
}

/// Cause for closing a Charging Data Record (CDR) (TS 32.255 Section 5.3.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CdrClosingCause {
    NormalRelease,
    AbnormalRelease,
    VolumeLimit,
    TimeLimit,
    ManagementIntervention,
}

/// 5G Offline Charging Data Record (CDR) for PDU Sessions (TS 32.298 / TS 32.255).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PduSessionChargingRecord {
    pub cdr_id: String,
    pub supi: String,
    pub pdu_session_id: u8,
    pub charging_id: u32,
    pub s_nssai: Snssai,
    pub rating_group: u32,
    pub start_time_epoch_s: u64,
    pub stop_time_epoch_s: u64,
    pub duration_s: u32,
    pub total_volume_bytes: u64,
    pub uplink_volume_bytes: u64,
    pub downlink_volume_bytes: u64,
    pub total_amount_debited_cents: u64,
    pub cause_for_closing: CdrClosingCause,
}

// ---------------------------------------------------------------------------
// Rating Plans & Subscriber Accounts
// ---------------------------------------------------------------------------

/// Rating plan configuration for a Rating Group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatingPlan {
    pub rating_group: u32,
    /// Cost in cents per Megabyte (1,000,000 bytes)
    pub cents_per_megabyte: u64,
}

/// Subscriber prepaid/postpaid account maintained in CHF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriberAccount {
    pub supi: String,
    pub balance_cents: u64,
    pub reserved_cents: u64,
}

impl SubscriberAccount {
    pub fn new(supi: &str, initial_balance_cents: u64) -> Self {
        SubscriberAccount {
            supi: supi.to_string(),
            balance_cents: initial_balance_cents,
            reserved_cents: 0,
        }
    }

    /// Available unreserved balance in cents.
    pub fn available_balance(&self) -> u64 {
        self.balance_cents.saturating_sub(self.reserved_cents)
    }
}

/// 5G CHF Subscriber Account alias for disambiguation with 4G Diameter account.
pub type ChfSubscriberAccount = SubscriberAccount;

// ---------------------------------------------------------------------------
// Nchf_ConvergedCharging Service Operations (TS 32.291 Section 5.2)
// ---------------------------------------------------------------------------

/// Initial Charging Request (SMF -> CHF).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitialChargingRequest {
    pub supi: String,
    pub pdu_session_id: u8,
    pub s_nssai: Snssai,
    pub rating_group: u32,
    pub requested_volume_bytes: u64,
    pub timestamp_epoch_s: u64,
}

/// Initial Charging Response (CHF -> SMF).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitialChargingResponse {
    pub charging_session_id: String,
    pub granted_quota: Option<GrantedQuotaUnit>,
    pub final_unit_indication: Option<FinalUnitIndication>,
}

/// Update Charging Request (SMF -> CHF).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateChargingRequest {
    pub charging_session_id: String,
    pub used_quota: UsedQuotaUnit,
    pub requested_volume_bytes: Option<u64>,
    pub timestamp_epoch_s: u64,
}

/// Update Charging Response (CHF -> SMF).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateChargingResponse {
    pub granted_quota: Option<GrantedQuotaUnit>,
    pub final_unit_indication: Option<FinalUnitIndication>,
    pub remaining_balance_cents: u64,
}

/// Termination Charging Request (SMF -> CHF).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminationChargingRequest {
    pub charging_session_id: String,
    pub final_used_quota: UsedQuotaUnit,
    pub timestamp_epoch_s: u64,
    pub closing_cause: CdrClosingCause,
}

/// Termination Charging Response (CHF -> SMF).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminationChargingResponse {
    pub generated_cdr_id: String,
    pub final_balance_cents: u64,
}

// ---------------------------------------------------------------------------
// Charging Session Context & Top-Level CHF Engine
// ---------------------------------------------------------------------------

/// Active charging session state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChfSessionContext {
    pub session_id: String,
    pub supi: String,
    pub pdu_session_id: u8,
    pub s_nssai: Snssai,
    pub rating_group: u32,
    pub state: ChargingSessionState,
    pub start_time_epoch_s: u64,
    pub last_update_epoch_s: u64,
    pub currently_reserved_cents: u64,
    pub total_used_volume_bytes: u64,
    pub total_uplink_bytes: u64,
    pub total_downlink_bytes: u64,
    pub total_debited_cents: u64,
    pub charging_id: u32,
}

/// 5G Converged Charging Function (CHF) Engine.
pub struct ChfEngine {
    pub chf_instance_id: String,
    pub next_session_counter: u32,
    pub next_cdr_counter: u32,
    pub accounts: HashMap<String, SubscriberAccount>, // supi -> account
    pub rating_plans: HashMap<u32, RatingPlan>,       // rating_group -> plan
    pub active_sessions: HashMap<String, ChfSessionContext>, // session_id -> context
    pub generated_cdrs: Vec<PduSessionChargingRecord>,
}

impl ChfEngine {
    /// Create a new CHF engine instance.
    pub fn new(chf_instance_id: &str) -> Self {
        let mut rating_plans = HashMap::new();
        // Default Web/Internet: 5 cents per MB
        rating_plans.insert(
            100,
            RatingPlan {
                rating_group: 100,
                cents_per_megabyte: 5,
            },
        );
        // Video Streaming: 10 cents per MB
        rating_plans.insert(
            200,
            RatingPlan {
                rating_group: 200,
                cents_per_megabyte: 10,
            },
        );
        // Low Latency Gaming: 15 cents per MB
        rating_plans.insert(
            300,
            RatingPlan {
                rating_group: 300,
                cents_per_megabyte: 15,
            },
        );

        ChfEngine {
            chf_instance_id: chf_instance_id.to_string(),
            next_session_counter: 1001,
            next_cdr_counter: 5001,
            accounts: HashMap::new(),
            rating_plans,
            active_sessions: HashMap::new(),
            generated_cdrs: Vec::new(),
        }
    }

    /// Provision a subscriber account with initial prepaid balance.
    pub fn provision_account(&mut self, supi: &str, initial_balance_cents: u64) {
        self.accounts.insert(
            supi.to_string(),
            SubscriberAccount::new(supi, initial_balance_cents),
        );
    }

    /// Configure a custom rating plan for a Rating Group.
    pub fn set_rating_plan(&mut self, rating_group: u32, cents_per_megabyte: u64) {
        self.rating_plans.insert(
            rating_group,
            RatingPlan {
                rating_group,
                cents_per_megabyte,
            },
        );
    }

    /// Nchf_ConvergedCharging_Create: Start session-based charging and grant initial quota.
    pub fn handle_initial_request(
        &mut self,
        req: &InitialChargingRequest,
    ) -> Result<InitialChargingResponse, &'static str> {
        let plan = self
            .rating_plans
            .get(&req.rating_group)
            .ok_or("Rating group not found")?;

        let acct = self
            .accounts
            .get_mut(&req.supi)
            .ok_or("Subscriber account not found")?;

        let session_id = format!("urn:chf:session:{}", self.next_session_counter);
        let charging_id = self.next_session_counter;
        self.next_session_counter += 1;

        // Calculate cost for requested volume (in MB rounded up)
        let req_mb = (req.requested_volume_bytes + 999_999) / 1_000_000;
        let required_cost_cents = req_mb * plan.cents_per_megabyte;

        let available = acct.available_balance();

        if available == 0 {
            // Immediate credit exhaustion
            return Ok(InitialChargingResponse {
                charging_session_id: session_id,
                granted_quota: None,
                final_unit_indication: Some(FinalUnitIndication {
                    action: FinalUnitAction::Redirect {
                        redirect_server_url: "https://selfcare.carrier.com/topup".to_string(),
                    },
                }),
            });
        }

        // Reserve cost (cap at available balance)
        let cost_to_reserve = required_cost_cents.min(available);
        acct.reserved_cents += cost_to_reserve;

        // Calculate granted bytes based on reserved cost
        let granted_mb = cost_to_reserve / plan.cents_per_megabyte;
        let granted_bytes = (granted_mb * 1_000_000).max(1_000_000);

        let gqu = GrantedQuotaUnit {
            total_volume_bytes: granted_bytes,
            uplink_volume_bytes: granted_bytes / 4,
            downlink_volume_bytes: (granted_bytes * 3) / 4,
            validity_time_s: 3600,
            quota_threshold_volume_bytes: Some((granted_bytes * 8) / 10), // 80% threshold
        };

        let ctx = ChfSessionContext {
            session_id: session_id.clone(),
            supi: req.supi.clone(),
            pdu_session_id: req.pdu_session_id,
            s_nssai: req.s_nssai.clone(),
            rating_group: req.rating_group,
            state: ChargingSessionState::Active,
            start_time_epoch_s: req.timestamp_epoch_s,
            last_update_epoch_s: req.timestamp_epoch_s,
            currently_reserved_cents: cost_to_reserve,
            total_used_volume_bytes: 0,
            total_uplink_bytes: 0,
            total_downlink_bytes: 0,
            total_debited_cents: 0,
            charging_id,
        };

        self.active_sessions.insert(session_id.clone(), ctx);

        Ok(InitialChargingResponse {
            charging_session_id: session_id,
            granted_quota: Some(gqu),
            final_unit_indication: None,
        })
    }

    /// Nchf_ConvergedCharging_Update: Debit consumed quota and grant fresh quota.
    pub fn handle_update_request(
        &mut self,
        req: &UpdateChargingRequest,
    ) -> Result<UpdateChargingResponse, &'static str> {
        let ctx = self
            .active_sessions
            .get_mut(&req.charging_session_id)
            .ok_or("Charging session not found")?;

        let plan = self
            .rating_plans
            .get(&ctx.rating_group)
            .ok_or("Rating group not found")?;

        let acct = self
            .accounts
            .get_mut(&ctx.supi)
            .ok_or("Subscriber account not found")?;

        // 1. Calculate cost for reported consumed volume
        let consumed_mb = (req.used_quota.total_volume_bytes + 999_999) / 1_000_000;
        let debit_cost_cents = consumed_mb * plan.cents_per_megabyte;

        // 2. Reconcile reservation and debit account balance
        acct.reserved_cents = acct
            .reserved_cents
            .saturating_sub(ctx.currently_reserved_cents);
        acct.balance_cents = acct.balance_cents.saturating_sub(debit_cost_cents);

        ctx.total_used_volume_bytes += req.used_quota.total_volume_bytes;
        ctx.total_uplink_bytes += req.used_quota.uplink_volume_bytes;
        ctx.total_downlink_bytes += req.used_quota.downlink_volume_bytes;
        ctx.total_debited_cents += debit_cost_cents;
        ctx.last_update_epoch_s = req.timestamp_epoch_s;

        let available = acct.available_balance();

        if available == 0 {
            // Out of credit -> Trigger Final Unit Indication
            ctx.state = ChargingSessionState::FinalUnitReached;
            ctx.currently_reserved_cents = 0;

            return Ok(UpdateChargingResponse {
                granted_quota: None,
                final_unit_indication: Some(FinalUnitIndication {
                    action: FinalUnitAction::RestrictAccess {
                        max_bitrate_kbps: 64,
                    },
                }),
                remaining_balance_cents: acct.balance_cents,
            });
        }

        // Grant fresh quota
        let req_bytes = req.requested_volume_bytes.unwrap_or(10_000_000);
        let req_mb = (req_bytes + 999_999) / 1_000_000;
        let required_cost_cents = req_mb * plan.cents_per_megabyte;

        let cost_to_reserve = required_cost_cents.min(available);
        acct.reserved_cents += cost_to_reserve;
        ctx.currently_reserved_cents = cost_to_reserve;

        let granted_mb = cost_to_reserve / plan.cents_per_megabyte;
        let granted_bytes = (granted_mb * 1_000_000).max(1_000_000);

        let gqu = GrantedQuotaUnit {
            total_volume_bytes: granted_bytes,
            uplink_volume_bytes: granted_bytes / 4,
            downlink_volume_bytes: (granted_bytes * 3) / 4,
            validity_time_s: 3600,
            quota_threshold_volume_bytes: Some((granted_bytes * 8) / 10),
        };

        Ok(UpdateChargingResponse {
            granted_quota: Some(gqu),
            final_unit_indication: None,
            remaining_balance_cents: acct.balance_cents,
        })
    }

    /// Nchf_ConvergedCharging_Release: Finalize session, commit offline CDR.
    pub fn handle_termination_request(
        &mut self,
        req: &TerminationChargingRequest,
    ) -> Result<TerminationChargingResponse, &'static str> {
        let mut ctx = self
            .active_sessions
            .remove(&req.charging_session_id)
            .ok_or("Charging session not found")?;

        let plan = self
            .rating_plans
            .get(&ctx.rating_group)
            .ok_or("Rating group not found")?;

        let acct = self
            .accounts
            .get_mut(&ctx.supi)
            .ok_or("Subscriber account not found")?;

        // 1. Debit any final delta volume
        let final_mb = (req.final_used_quota.total_volume_bytes + 999_999) / 1_000_000;
        let final_cost = final_mb * plan.cents_per_megabyte;

        acct.reserved_cents = acct
            .reserved_cents
            .saturating_sub(ctx.currently_reserved_cents);
        acct.balance_cents = acct.balance_cents.saturating_sub(final_cost);

        ctx.total_used_volume_bytes += req.final_used_quota.total_volume_bytes;
        ctx.total_uplink_bytes += req.final_used_quota.uplink_volume_bytes;
        ctx.total_downlink_bytes += req.final_used_quota.downlink_volume_bytes;
        ctx.total_debited_cents += final_cost;
        ctx.state = ChargingSessionState::Terminated;

        // 2. Commit immutable CDR
        let cdr_id = format!("cdr-5gc-{}", self.next_cdr_counter);
        self.next_cdr_counter += 1;

        let cdr = PduSessionChargingRecord {
            cdr_id: cdr_id.clone(),
            supi: ctx.supi.clone(),
            pdu_session_id: ctx.pdu_session_id,
            charging_id: ctx.charging_id,
            s_nssai: ctx.s_nssai,
            rating_group: ctx.rating_group,
            start_time_epoch_s: ctx.start_time_epoch_s,
            stop_time_epoch_s: req.timestamp_epoch_s,
            duration_s: (req.timestamp_epoch_s.saturating_sub(ctx.start_time_epoch_s)) as u32,
            total_volume_bytes: ctx.total_used_volume_bytes,
            uplink_volume_bytes: ctx.total_uplink_bytes,
            downlink_volume_bytes: ctx.total_downlink_bytes,
            total_amount_debited_cents: ctx.total_debited_cents,
            cause_for_closing: req.closing_cause,
        };

        self.generated_cdrs.push(cdr);

        Ok(TerminationChargingResponse {
            generated_cdr_id: cdr_id,
            final_balance_cents: acct.balance_cents,
        })
    }
}

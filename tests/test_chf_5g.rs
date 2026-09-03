//! Integration tests for 3GPP TS 32.291 / TS 32.255 5G Converged Charging Function (CHF) Engine.

use toy_tcpip::chf_5g::*;
use toy_tcpip::ngap_5g::Snssai;

// ---------------------------------------------------------------------------
// 1. Initial Charging Request & Quota Grant Happy Path
// ---------------------------------------------------------------------------

#[test]
fn test_chf_initial_request_and_quota_grant() {
    let mut chf = ChfEngine::new("chf-core-001");
    let supi = "imsi-208950000000001";
    chf.provision_account(supi, 1000); // 1000 cents ($10.00)

    let req = InitialChargingRequest {
        supi: supi.to_string(),
        pdu_session_id: 1,
        s_nssai: Snssai { sst: 1, sd: None },
        rating_group: 100,                  // Web: 5 cents/MB
        requested_volume_bytes: 50_000_000, // 50 MB
        timestamp_epoch_s: 1700000000,
    };

    let resp = chf
        .handle_initial_request(&req)
        .expect("Initial charging failed");

    assert!(!resp.charging_session_id.is_empty());
    assert!(resp.final_unit_indication.is_none());

    let gqu = resp.granted_quota.expect("Granted quota missing");
    assert_eq!(gqu.total_volume_bytes, 50_000_000);
    assert_eq!(gqu.validity_time_s, 3600);
    assert_eq!(gqu.quota_threshold_volume_bytes, Some(40_000_000)); // 80%

    // Verify account reservation
    let acct = chf.accounts.get(supi).unwrap();
    assert_eq!(acct.reserved_cents, 250); // 50 MB * 5 cents = 250 cents
    assert_eq!(acct.available_balance(), 750);
}

// ---------------------------------------------------------------------------
// 2. Update Charging Request & Account Debiting
// ---------------------------------------------------------------------------

#[test]
fn test_chf_update_request_and_debit_reconciliation() {
    let mut chf = ChfEngine::new("chf-core-002");
    let supi = "imsi-208950000000002";
    chf.provision_account(supi, 1000);

    let init_req = InitialChargingRequest {
        supi: supi.to_string(),
        pdu_session_id: 1,
        s_nssai: Snssai { sst: 1, sd: None },
        rating_group: 100,
        requested_volume_bytes: 20_000_000, // 20 MB = 100 cents
        timestamp_epoch_s: 1700000000,
    };
    let init_resp = chf.handle_initial_request(&init_req).unwrap();

    // SMF reports 20 MB consumed
    let update_req = UpdateChargingRequest {
        charging_session_id: init_resp.charging_session_id,
        used_quota: UsedQuotaUnit {
            rating_group: 100,
            total_volume_bytes: 20_000_000,
            uplink_volume_bytes: 5_000_000,
            downlink_volume_bytes: 15_000_000,
            reporting_reason: ReportingReason::ThresholdReached,
        },
        requested_volume_bytes: Some(10_000_000), // Request 10 MB more
        timestamp_epoch_s: 1700000100,
    };

    let update_resp = chf.handle_update_request(&update_req).unwrap();
    assert!(update_resp.final_unit_indication.is_none());
    assert!(update_resp.granted_quota.is_some());

    // Balance debited by 100 cents (from 1000 to 900)
    assert_eq!(update_resp.remaining_balance_cents, 900);
}

// ---------------------------------------------------------------------------
// 3. Credit Exhaustion -> Final Unit Indication
// ---------------------------------------------------------------------------

#[test]
fn test_chf_out_of_credit_final_unit_indication() {
    let mut chf = ChfEngine::new("chf-core-003");
    let supi = "imsi-208950000000003";
    // Tiny balance of only 5 cents (1 MB @ 5 cents/MB)
    chf.provision_account(supi, 5);

    let init_req = InitialChargingRequest {
        supi: supi.to_string(),
        pdu_session_id: 1,
        s_nssai: Snssai { sst: 1, sd: None },
        rating_group: 100,
        requested_volume_bytes: 1_000_000,
        timestamp_epoch_s: 1700000000,
    };
    let init_resp = chf.handle_initial_request(&init_req).unwrap();

    // Consume the 1 MB
    let update_req = UpdateChargingRequest {
        charging_session_id: init_resp.charging_session_id,
        used_quota: UsedQuotaUnit {
            rating_group: 100,
            total_volume_bytes: 1_000_000,
            uplink_volume_bytes: 200_000,
            downlink_volume_bytes: 800_000,
            reporting_reason: ReportingReason::ThresholdReached,
        },
        requested_volume_bytes: Some(5_000_000),
        timestamp_epoch_s: 1700000050,
    };

    let update_resp = chf.handle_update_request(&update_req).unwrap();
    assert!(update_resp.granted_quota.is_none());
    assert_eq!(update_resp.remaining_balance_cents, 0);

    let fui = update_resp.final_unit_indication.expect("FUI missing");
    assert_eq!(
        fui.action,
        FinalUnitAction::RestrictAccess {
            max_bitrate_kbps: 64
        }
    );
}

// ---------------------------------------------------------------------------
// 4. Session Termination & Offline CDR Generation
// ---------------------------------------------------------------------------

#[test]
fn test_chf_termination_and_cdr_generation() {
    let mut chf = ChfEngine::new("chf-core-004");
    let supi = "imsi-208950000000004";
    chf.provision_account(supi, 500);

    let init_req = InitialChargingRequest {
        supi: supi.to_string(),
        pdu_session_id: 2,
        s_nssai: Snssai { sst: 2, sd: None },
        rating_group: 200, // Video: 10 cents/MB
        requested_volume_bytes: 10_000_000,
        timestamp_epoch_s: 1700000000,
    };
    let init_resp = chf.handle_initial_request(&init_req).unwrap();

    // Terminate session after 60 seconds and 5 MB consumed
    let term_req = TerminationChargingRequest {
        charging_session_id: init_resp.charging_session_id,
        final_used_quota: UsedQuotaUnit {
            rating_group: 200,
            total_volume_bytes: 5_000_000,
            uplink_volume_bytes: 1_000_000,
            downlink_volume_bytes: 4_000_000,
            reporting_reason: ReportingReason::SessionTermination,
        },
        timestamp_epoch_s: 1700000060,
        closing_cause: CdrClosingCause::NormalRelease,
    };

    let term_resp = chf.handle_termination_request(&term_req).unwrap();
    assert!(!term_resp.generated_cdr_id.is_empty());
    // 500 - (5 MB * 10 cents = 50 cents) = 450 cents
    assert_eq!(term_resp.final_balance_cents, 450);

    // Verify generated CDR record
    assert_eq!(chf.generated_cdrs.len(), 1);
    let cdr = &chf.generated_cdrs[0];
    assert_eq!(cdr.supi, supi);
    assert_eq!(cdr.pdu_session_id, 2);
    assert_eq!(cdr.duration_s, 60);
    assert_eq!(cdr.total_volume_bytes, 5_000_000);
    assert_eq!(cdr.total_amount_debited_cents, 50);
    assert_eq!(cdr.cause_for_closing, CdrClosingCause::NormalRelease);
}

// ---------------------------------------------------------------------------
// 5. Differential Rating Plans
// ---------------------------------------------------------------------------

#[test]
fn test_chf_differential_rating_groups() {
    let mut chf = ChfEngine::new("chf-core-005");
    let supi = "imsi-208950000000005";
    chf.provision_account(supi, 1000);

    // Rating Group 300 (Gaming) = 15 cents/MB
    let req = InitialChargingRequest {
        supi: supi.to_string(),
        pdu_session_id: 1,
        s_nssai: Snssai { sst: 1, sd: None },
        rating_group: 300,
        requested_volume_bytes: 10_000_000, // 10 MB = 150 cents
        timestamp_epoch_s: 1700000000,
    };

    let resp = chf.handle_initial_request(&req).unwrap();
    assert!(resp.granted_quota.is_some());

    let acct = chf.accounts.get(supi).unwrap();
    assert_eq!(acct.reserved_cents, 150); // 10 MB * 15 cents
}

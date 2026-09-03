//! Integration tests for 3GPP TS 29.522 / TS 23.501 / TS 29.512 5G Background Data Transfer (BDT).

use toy_tcpip::bdt_5g::*;

// ---------------------------------------------------------------------------
// 1. BDT Policy Negotiation and Traffic Accounting Happy Path
// ---------------------------------------------------------------------------

#[test]
fn test_bdt_negotiation_and_traffic_accounting_happy_path() {
    let mut bdt = BdtEngine::new("tokyo-core");

    let req = BdtTransferRequest {
        af_id: "tesla-ota-fleet".to_string(),
        volume_per_ue_bytes: 50_000_000, // 50 MB per car
        number_of_ues: 1_000,            // 1,000 cars (total 50 GB)
        desired_window: TimeWindow {
            start_time_epoch_s: 1700000000,
            end_time_epoch_s: 1700000000 + 86400, // next 24 hours
        },
        network_area_ta_list: vec!["tai-440-53-001".to_string(), "tai-440-53-002".to_string()],
    };

    // Step 1: Propose BDT
    let (bdt_ref_id, candidates) = bdt.propose_bdt_negotiation(req).unwrap();
    assert_eq!(candidates.len(), 2);
    assert_eq!(candidates[0].discount_percent, 80);
    assert_eq!(candidates[1].discount_percent, 50);

    // Step 2: AF chooses Policy 1 (80% discount)
    bdt.commit_bdt_policy(&bdt_ref_id, 1).unwrap();

    let sess = bdt.sessions.get(&bdt_ref_id).unwrap();
    assert_eq!(sess.state, BdtNegotiationState::Committed);

    // Step 3: Vehicle initiates download inside the permitted window
    let window = candidates[0].time_window;
    let mid_window_time = window.start_time_epoch_s + 1000;

    let rating_group = bdt
        .verify_and_account_traffic(&bdt_ref_id, mid_window_time, 10_000_000)
        .unwrap();

    assert_eq!(rating_group, 8001); // Discounted rating group

    let updated_sess = bdt.sessions.get(&bdt_ref_id).unwrap();
    assert_eq!(updated_sess.state, BdtNegotiationState::Active);
    assert_eq!(updated_sess.total_bytes_transferred, 10_000_000);
}

// ---------------------------------------------------------------------------
// 2. Outside Permitted Time Window Rejection
// ---------------------------------------------------------------------------

#[test]
fn test_bdt_outside_permitted_time_window_rejection() {
    let mut bdt = BdtEngine::new("osaka-core");

    let req = BdtTransferRequest {
        af_id: "smart-meter-grid".to_string(),
        volume_per_ue_bytes: 1_000_000,
        number_of_ues: 500,
        desired_window: TimeWindow {
            start_time_epoch_s: 1700000000,
            end_time_epoch_s: 1700000000 + 43200,
        },
        network_area_ta_list: vec!["tai-osaka-1".to_string()],
    };

    let (bdt_ref_id, candidates) = bdt.propose_bdt_negotiation(req).unwrap();
    bdt.commit_bdt_policy(&bdt_ref_id, 1).unwrap();

    let window = candidates[0].time_window;

    // Too early (before window starts)
    let early_time = window.start_time_epoch_s - 60;
    let err_early = bdt.verify_and_account_traffic(&bdt_ref_id, early_time, 5000);
    match err_early {
        Err(BdtError::OutsidePermittedTimeWindow { current, start, .. }) => {
            assert_eq!(current, early_time);
            assert_eq!(start, window.start_time_epoch_s);
        }
        _ => panic!("Expected OutsidePermittedTimeWindow"),
    }

    // Too late (after window ends)
    let late_time = window.end_time_epoch_s + 60;
    let err_late = bdt.verify_and_account_traffic(&bdt_ref_id, late_time, 5000);
    assert!(matches!(
        err_late,
        Err(BdtError::OutsidePermittedTimeWindow { .. })
    ));
}

// ---------------------------------------------------------------------------
// 3. Volume Quota Exceeded Rejection
// ---------------------------------------------------------------------------

#[test]
fn test_bdt_volume_quota_exceeded_rejection() {
    let mut bdt = BdtEngine::new("nagoya-core");

    let req = BdtTransferRequest {
        af_id: "iot-sensors".to_string(),
        volume_per_ue_bytes: 1000,
        number_of_ues: 2, // Total quota = 2,000 bytes
        desired_window: TimeWindow {
            start_time_epoch_s: 1700000000,
            end_time_epoch_s: 1700000000 + 36000,
        },
        network_area_ta_list: vec!["tai-nagoya".to_string()],
    };

    let (bdt_ref_id, candidates) = bdt.propose_bdt_negotiation(req).unwrap();
    bdt.commit_bdt_policy(&bdt_ref_id, 1).unwrap();

    let valid_time = candidates[0].time_window.start_time_epoch_s + 10;

    // First chunk: 1,500 bytes (OK)
    bdt.verify_and_account_traffic(&bdt_ref_id, valid_time, 1500)
        .unwrap();

    // Second chunk: 600 bytes (Total = 2,100 > 2,000 -> Exceeded!)
    let err = bdt.verify_and_account_traffic(&bdt_ref_id, valid_time, 600);
    match err {
        Err(BdtError::TransferVolumeQuotaExceeded {
            transferred,
            max_allowed,
        }) => {
            assert_eq!(transferred, 2100);
            assert_eq!(max_allowed, 2000);
        }
        _ => panic!("Expected TransferVolumeQuotaExceeded"),
    }
}

// ---------------------------------------------------------------------------
// 4. Rejection and Uncommitted Access
// ---------------------------------------------------------------------------

#[test]
fn test_bdt_rejection_and_uncommitted_access() {
    let mut bdt = BdtEngine::new("fukuoka-core");

    let req = BdtTransferRequest {
        af_id: "drone-feed".to_string(),
        volume_per_ue_bytes: 10_000,
        number_of_ues: 5,
        desired_window: TimeWindow {
            start_time_epoch_s: 1700000000,
            end_time_epoch_s: 1700000000 + 10000,
        },
        network_area_ta_list: vec![],
    };

    let (bdt_ref_id, _) = bdt.propose_bdt_negotiation(req).unwrap();

    // Try to transfer before committing
    let err_uncommitted = bdt.verify_and_account_traffic(&bdt_ref_id, 1700005000, 100);
    assert_eq!(err_uncommitted, Err(BdtError::SessionNotCommitted));

    // Reject negotiation
    bdt.reject_bdt_negotiation(&bdt_ref_id).unwrap();
    assert_eq!(
        bdt.sessions.get(&bdt_ref_id).unwrap().state,
        BdtNegotiationState::Rejected
    );

    // Try to transfer after rejection
    let err_rejected = bdt.verify_and_account_traffic(&bdt_ref_id, 1700005000, 100);
    assert_eq!(err_rejected, Err(BdtError::SessionNotCommitted));
}

// ---------------------------------------------------------------------------
// 5. Error Handling: Invalid Window and Zero Parameters
// ---------------------------------------------------------------------------

#[test]
fn test_bdt_error_handling_invalid_window_or_zero_values() {
    let mut bdt = BdtEngine::new("err-core");

    // Zero volume
    let err1 = bdt.propose_bdt_negotiation(BdtTransferRequest {
        af_id: "af1".to_string(),
        volume_per_ue_bytes: 0,
        number_of_ues: 10,
        desired_window: TimeWindow {
            start_time_epoch_s: 100,
            end_time_epoch_s: 200,
        },
        network_area_ta_list: vec![],
    });
    assert_eq!(err1, Err(BdtError::ZeroVolumeOrUes));

    // Invalid time window (start >= end)
    let err2 = bdt.propose_bdt_negotiation(BdtTransferRequest {
        af_id: "af2".to_string(),
        volume_per_ue_bytes: 100,
        number_of_ues: 10,
        desired_window: TimeWindow {
            start_time_epoch_s: 200,
            end_time_epoch_s: 100,
        },
        network_area_ta_list: vec![],
    });
    assert_eq!(err2, Err(BdtError::InvalidTimeWindow));

    // Non-existent policy commit
    let (ref_id, _) = bdt
        .propose_bdt_negotiation(BdtTransferRequest {
            af_id: "af3".to_string(),
            volume_per_ue_bytes: 100,
            number_of_ues: 10,
            desired_window: TimeWindow {
                start_time_epoch_s: 100,
                end_time_epoch_s: 200,
            },
            network_area_ta_list: vec![],
        })
        .unwrap();

    let err3 = bdt.commit_bdt_policy(&ref_id, 999);
    assert_eq!(err3, Err(BdtError::PolicyNotFound { policy_id: 999 }));
}

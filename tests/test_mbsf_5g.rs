//! Integration tests for 3GPP TS 29.580 / TS 29.581 / TS 23.247 5G 5MBS (Multicast/Broadcast Services).

use toy_tcpip::mbsf_5g::*;

// ---------------------------------------------------------------------------
// 1. Broadcast Session Lifecycle Happy Path
// ---------------------------------------------------------------------------

#[test]
fn test_mbsf_broadcast_session_lifecycle() {
    let mut mbsf = MbsfEngine::new("mbsf-core-01", "208", "95");

    let sess_id = mbsf.create_mbs_session(
        MbsServiceType::Broadcast,
        vec!["tai-tokyo-01".to_string(), "tai-tokyo-02".to_string()],
        75, // 5QI 75 for Live Uplink/Broadcast Video
        MbsDeliveryMethod::PtmOnly,
        1,
    );

    assert!(sess_id.contains("mbs-sess-"));
    let sess = mbsf.sessions.get(&sess_id).unwrap();
    assert_eq!(sess.service_type, MbsServiceType::Broadcast);
    assert_eq!(sess.state, MbsSessionState::Configured);
    assert_eq!(sess.qos_5qi, 75);

    // Activate session
    mbsf.activate_mbs_session(&sess_id).unwrap();
    assert_eq!(
        mbsf.sessions.get(&sess_id).unwrap().state,
        MbsSessionState::Active
    );

    // Release session
    mbsf.release_mbs_session(&sess_id).unwrap();
    assert!(!mbsf.sessions.contains_key(&sess_id));
}

// ---------------------------------------------------------------------------
// 2. Multicast UE Join and Leave Operations
// ---------------------------------------------------------------------------

#[test]
fn test_mbsf_multicast_ue_join_and_leave() {
    let mut mbsf = MbsfEngine::new("mbsf-core-02", "208", "95");

    let sess_id = mbsf.create_mbs_session(
        MbsServiceType::Multicast,
        vec!["tai-stadium-01".to_string()],
        75,
        MbsDeliveryMethod::DynamicPtmPtp,
        3,
    );

    let ue1 = "imsi-208950000000001";
    let ue2 = "imsi-208950000000002";

    // UE 1 joins
    mbsf.ue_join_multicast_session(&sess_id, ue1).unwrap();
    assert!(
        mbsf.sessions
            .get(&sess_id)
            .unwrap()
            .joined_ue_supis
            .contains(ue1)
    );

    // Duplicate join should fail
    let dup_err = mbsf.ue_join_multicast_session(&sess_id, ue1);
    assert_eq!(dup_err, Err(MbsError::UeAlreadyJoined));

    // UE 2 joins
    mbsf.ue_join_multicast_session(&sess_id, ue2).unwrap();
    assert_eq!(
        mbsf.sessions.get(&sess_id).unwrap().joined_ue_supis.len(),
        2
    );

    // UE 1 leaves
    mbsf.ue_leave_multicast_session(&sess_id, ue1).unwrap();
    assert!(
        !mbsf
            .sessions
            .get(&sess_id)
            .unwrap()
            .joined_ue_supis
            .contains(ue1)
    );

    // UE 1 leaves again -> error
    let leave_err = mbsf.ue_leave_multicast_session(&sess_id, ue1);
    assert_eq!(leave_err, Err(MbsError::UeNotJoined));
}

// ---------------------------------------------------------------------------
// 3. Dynamic PTM vs PTP Delivery Mode Switching
// ---------------------------------------------------------------------------

#[test]
fn test_mbsf_dynamic_ptm_ptp_switching() {
    let mut mbsf = MbsfEngine::new("mbsf-core-03", "466", "92");

    let sess_id = mbsf.create_mbs_session(
        MbsServiceType::Multicast,
        vec!["tai-metro-01".to_string()],
        79, // 5QI 79 for V2X / Critical Broadcast
        MbsDeliveryMethod::DynamicPtmPtp,
        4, // PTM threshold: 4 UEs
    );

    // Cell A: 2 UEs active (< 4) -> PointToPoint unicast fallback
    let mode_sparse = mbsf.evaluate_cell_delivery_mode(&sess_id, 2).unwrap();
    assert_eq!(mode_sparse, CellDeliveryMode::PointToPoint);

    // Cell B: Exactly 4 UEs active (== 4) -> PointToMultipoint broadcast
    let mode_exact = mbsf.evaluate_cell_delivery_mode(&sess_id, 4).unwrap();
    assert_eq!(mode_exact, CellDeliveryMode::PointToMultipoint);

    // Cell C: 20 UEs active (> 4) -> PointToMultipoint broadcast
    let mode_dense = mbsf.evaluate_cell_delivery_mode(&sess_id, 20).unwrap();
    assert_eq!(mode_dense, CellDeliveryMode::PointToMultipoint);
}

// ---------------------------------------------------------------------------
// 4. Broadcast Rejects UE Join
// ---------------------------------------------------------------------------

#[test]
fn test_mbsf_broadcast_rejects_ue_join() {
    let mut mbsf = MbsfEngine::new("mbsf-core-04", "208", "95");

    let sess_id = mbsf.create_mbs_session(
        MbsServiceType::Broadcast,
        vec!["tai-national".to_string()],
        75,
        MbsDeliveryMethod::PtmOnly,
        1,
    );

    let err = mbsf.ue_join_multicast_session(&sess_id, "imsi-12345");
    assert_eq!(
        err,
        Err(MbsError::InvalidServiceType(
            "UE Join is only applicable to Multicast service type"
        ))
    );
}

// ---------------------------------------------------------------------------
// 5. Session Not Found Handling
// ---------------------------------------------------------------------------

#[test]
fn test_mbsf_session_not_found_handling() {
    let mut mbsf = MbsfEngine::new("mbsf-core-05", "208", "95");

    let err1 = mbsf.activate_mbs_session("non-existent-session");
    assert_eq!(err1, Err(MbsError::SessionNotFound));

    let err2 = mbsf.evaluate_cell_delivery_mode("non-existent-session", 5);
    assert_eq!(err2, Err(MbsError::SessionNotFound));
}

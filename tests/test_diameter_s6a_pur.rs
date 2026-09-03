use toy_tcpip::diameter_s6a_pur::{
    PUA_FLAG_FREEZE_M_TMSI, PUA_FLAG_FREEZE_P_TMSI, RESULT_CODE_SUCCESS, RESULT_CODE_USER_UNKNOWN,
    S6aPurEngine, S6aPurMessage,
};

#[test]
fn test_diameter_s6a_pur_lifecycle() {
    let mut engine = S6aPurEngine::new();
    let imsi_known = "310260123456789";
    let imsi_unknown = "999990000000001";

    // ── Step 1: Provision a subscriber ───────────────────────────────────
    engine.add_subscriber(imsi_known);
    assert!(engine.is_known(imsi_known));
    assert!(engine.is_attached(imsi_known));

    // ── Step 2: Purge unknown subscriber → USER_UNKNOWN ──────────────────
    let pur_unknown = S6aPurMessage::new_pur("sess-001", imsi_unknown, 0);
    let pua_unknown = engine.process_pur(&pur_unknown);
    assert!(!pua_unknown.is_request);
    assert_eq!(pua_unknown.result_code(), Some(RESULT_CODE_USER_UNKNOWN));
    assert_eq!(engine.purge_log().len(), 0);

    // ── Step 3: Purge known subscriber with both freeze flags ────────────
    engine.advance_clock(5_000_000);
    let flags = PUA_FLAG_FREEZE_M_TMSI | PUA_FLAG_FREEZE_P_TMSI;
    let pur_known = S6aPurMessage::new_pur("sess-002", imsi_known, flags);
    let pua_known = engine.process_pur(&pur_known);
    assert_eq!(pua_known.result_code(), Some(RESULT_CODE_SUCCESS));
    assert_eq!(pua_known.pua_flags(), flags);

    // Subscriber should now be detached.
    assert!(!engine.is_attached(imsi_known));

    // Purge log should contain 1 entry.
    let log = engine.purge_log();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].imsi, imsi_known);
    assert_eq!(log[0].purged_at_ns, 5_000_000);
    assert!(log[0].context_released);
    assert_eq!(log[0].flags, flags);

    // ── Step 4: Purge again (already detached) → still SUCCESS ───────────
    engine.advance_clock(1_000_000);
    let pur_again = S6aPurMessage::new_pur("sess-003", imsi_known, 0);
    let pua_again = engine.process_pur(&pur_again);
    assert_eq!(pua_again.result_code(), Some(RESULT_CODE_SUCCESS));
    assert_eq!(engine.purge_log().len(), 2);

    // ── Step 5: Verify message accessors ─────────────────────────────────
    assert_eq!(pur_known.session_id(), Some("sess-002"));
    assert_eq!(pur_known.imsi(), Some(imsi_known));
    assert_eq!(pur_known.command_code, 321);
}

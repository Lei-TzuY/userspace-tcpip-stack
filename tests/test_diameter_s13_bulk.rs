use toy_tcpip::diameter_s13_bulk::{BulkBlacklistAction, S13BulkEngine, S13BulkMessage};

#[test]
fn test_diameter_s13_bulk_lifecycle() {
    let mut engine = S13BulkEngine::new(
        "mme01.epc.mnc001.mcc208.3gppnetwork.org",
        "epc.mnc001.mcc208.3gppnetwork.org",
    );

    // 1. Initial Batch Add (Version 500)
    let imeis_add = vec!["860000000000010", "860000000000020", "860000000000030"];
    let bbr1 = S13BulkMessage::new_bbr(
        "sess-bulk-test-01",
        "eir01.epc.mnc001.mcc208.3gppnetwork.org",
        "epc.mnc001.mcc208.3gppnetwork.org",
        "epc.mnc001.mcc208.3gppnetwork.org",
        500,
        BulkBlacklistAction::Add,
        &imeis_add,
    );

    let bba1 = engine.process_bbr(&bbr1);
    assert_eq!(bba1.result_code, Some(2001)); // DIAMETER_SUCCESS
    assert_eq!(engine.current_version, 500);
    assert_eq!(engine.blacklisted_imeis.len(), 3);
    assert!(engine.is_blacklisted("860000000000020"));

    // 2. Incremental Remove (Version 501)
    let imeis_rem = vec!["860000000000020"];
    let bbr2 = S13BulkMessage::new_bbr(
        "sess-bulk-test-02",
        "eir01.epc.mnc001.mcc208.3gppnetwork.org",
        "epc.mnc001.mcc208.3gppnetwork.org",
        "epc.mnc001.mcc208.3gppnetwork.org",
        501,
        BulkBlacklistAction::Remove,
        &imeis_rem,
    );

    let bba2 = engine.process_bbr(&bbr2);
    assert_eq!(bba2.result_code, Some(2001));
    assert_eq!(engine.current_version, 501);
    assert_eq!(engine.blacklisted_imeis.len(), 2);
    assert!(!engine.is_blacklisted("860000000000020"));
}

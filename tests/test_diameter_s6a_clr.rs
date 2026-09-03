use toy_tcpip::diameter_s6a_clr::{
    CancellationType, DIAMETER_CMD_CANCEL_LOCATION, RESULT_CODE_SUCCESS, RESULT_CODE_USER_UNKNOWN,
    S6aClrEngine, S6aClrMessage,
};

#[test]
fn test_diameter_s6a_clr_lifecycle() {
    let mut mme = S6aClrEngine::new(
        "mme01.epc.mnc001.mcc208.3gppnetwork.org",
        "epc.mnc001.mcc208.3gppnetwork.org",
    );

    let imsi = "208950987654321";
    mme.attach_subscriber(imsi);

    assert_eq!(mme.active_subscribers.len(), 1);
    assert!(mme.active_subscribers[0].is_active);

    // 1. Send CLR for MmeUpdateProcedure
    let clr = S6aClrMessage::new_clr(
        "sess-clr-test-01",
        "hss01.epc.mnc001.mcc208.3gppnetwork.org",
        "epc.mnc001.mcc208.3gppnetwork.org",
        "mme01.epc.mnc001.mcc208.3gppnetwork.org",
        "epc.mnc001.mcc208.3gppnetwork.org",
        imsi,
        CancellationType::MmeUpdateProcedure,
        0,
    );
    assert_eq!(clr.command_code, DIAMETER_CMD_CANCEL_LOCATION);
    assert!(clr.is_request);

    let cla = mme.process_clr(&clr);
    assert_eq!(cla.result_code(), Some(RESULT_CODE_SUCCESS));
    assert!(!mme.active_subscribers[0].is_active);
    assert_eq!(
        mme.active_subscribers[0].cancellation_reason,
        Some(CancellationType::MmeUpdateProcedure)
    );

    // 2. Second CLR for unregistered subscriber
    let clr_unreg = S6aClrMessage::new_clr(
        "sess-clr-test-02",
        "hss01.epc.mnc001.mcc208.3gppnetwork.org",
        "epc.mnc001.mcc208.3gppnetwork.org",
        "mme01.epc.mnc001.mcc208.3gppnetwork.org",
        "epc.mnc001.mcc208.3gppnetwork.org",
        "460010000000000",
        CancellationType::SubscriptionWithdrawal,
        0,
    );
    let cla_unreg = mme.process_clr(&clr_unreg);
    assert_eq!(cla_unreg.result_code(), Some(RESULT_CODE_USER_UNKNOWN));

    assert_eq!(mme.total_clr_received, 2);
    assert_eq!(mme.total_cancelled_success, 1);
    assert_eq!(mme.total_rejected, 1);
}

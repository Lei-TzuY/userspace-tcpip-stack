use toy_tcpip::diameter_s6a_rsr::{
    DIAMETER_CMD_RESET, RESULT_CODE_SUCCESS, S6aRsrEngine, S6aRsrMessage,
};

#[test]
fn test_diameter_s6a_rsr_lifecycle() {
    let mut mme_engine = S6aRsrEngine::new(
        "mme01.epc.mnc001.mcc208.3gppnetwork.org",
        "epc.mnc001.mcc208.3gppnetwork.org",
    );

    let imsi1 = "208950000000001";
    let imsi2 = "208950000000002";
    let imsi3 = "208950000000003";

    mme_engine.provision_subscriber(imsi1);
    mme_engine.provision_subscriber(imsi2);
    mme_engine.provision_subscriber(imsi3);

    assert!(!mme_engine.needs_resync(imsi1));
    assert!(!mme_engine.needs_resync(imsi2));
    assert!(!mme_engine.needs_resync(imsi3));

    // ── Targeted RSR for imsi1 and imsi2 ──
    let rsr = S6aRsrMessage::new_rsr(
        "sess-rsr-test-101",
        "hss01.epc.mnc001.mcc208.3gppnetwork.org",
        "epc.mnc001.mcc208.3gppnetwork.org",
        "mme01.epc.mnc001.mcc208.3gppnetwork.org",
        "epc.mnc001.mcc208.3gppnetwork.org",
        &[imsi1, imsi2],
    );

    assert_eq!(rsr.command_code, DIAMETER_CMD_RESET);
    assert_eq!(rsr.user_ids(), vec![imsi1, imsi2]);

    let rsa = mme_engine.process_rsr(&rsr);
    assert!(!rsa.is_request);
    assert_eq!(rsa.result_code(), Some(RESULT_CODE_SUCCESS));

    assert!(mme_engine.needs_resync(imsi1));
    assert!(mme_engine.needs_resync(imsi2));
    assert!(!mme_engine.needs_resync(imsi3));

    // Clear resync for imsi1 after location update
    assert!(mme_engine.clear_resync(imsi1));
    assert!(!mme_engine.needs_resync(imsi1));

    // ── Global RSR for all subscribers ──
    let global_rsr = S6aRsrMessage::new_rsr(
        "sess-rsr-test-102",
        "hss01.epc.mnc001.mcc208.3gppnetwork.org",
        "epc.mnc001.mcc208.3gppnetwork.org",
        "mme01.epc.mnc001.mcc208.3gppnetwork.org",
        "epc.mnc001.mcc208.3gppnetwork.org",
        &[],
    );

    let global_rsa = mme_engine.process_rsr(&global_rsr);
    assert_eq!(global_rsa.result_code(), Some(RESULT_CODE_SUCCESS));

    assert!(mme_engine.needs_resync(imsi1));
    assert!(mme_engine.needs_resync(imsi2));
    assert!(mme_engine.needs_resync(imsi3));
}

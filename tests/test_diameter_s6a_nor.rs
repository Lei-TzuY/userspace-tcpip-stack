use toy_tcpip::diameter_s6a_nor::{
    DIAMETER_CMD_NOTIFY, NOR_FLAG_READY_FOR_SM, NOR_FLAG_SRVCC_SUPPORT, RESULT_CODE_SUCCESS,
    RESULT_CODE_USER_UNKNOWN, S6aNorEngine, S6aNorMessage,
};

#[test]
fn test_diameter_s6a_nor_lifecycle() {
    let mut hss = S6aNorEngine::new(
        "hss01.epc.mnc001.mcc208.3gppnetwork.org",
        "epc.mnc001.mcc208.3gppnetwork.org",
    );
    let imsi = "208950112233445";
    hss.register_subscriber(imsi);

    // 1. MME sends NOR with SRVCC & IMEI info
    let nor = S6aNorMessage::new_nor(
        "sess-nor-test-01",
        "mme01.epc.mnc001.mcc208.3gppnetwork.org",
        "epc.mnc001.mcc208.3gppnetwork.org",
        "hss01.epc.mnc001.mcc208.3gppnetwork.org",
        "epc.mnc001.mcc208.3gppnetwork.org",
        imsi,
        NOR_FLAG_SRVCC_SUPPORT | NOR_FLAG_READY_FOR_SM,
        Some("352099001234560"),
    );
    assert_eq!(nor.command_code, DIAMETER_CMD_NOTIFY);
    assert!(nor.is_request);

    let noa = hss.process_nor(&nor);
    assert_eq!(noa.result_code(), Some(RESULT_CODE_SUCCESS));

    let sub = hss.subscribers.iter().find(|s| s.imsi == imsi).unwrap();
    assert!(sub.srvcc_supported);
    assert!(sub.ready_for_sm);
    assert_eq!(sub.current_imei.as_deref(), Some("352099001234560"));

    // 2. NOR for unknown subscriber -> USER_UNKNOWN
    let nor_unreg = S6aNorMessage::new_nor(
        "sess-nor-test-02",
        "mme01.epc.mnc001.mcc208.3gppnetwork.org",
        "epc.mnc001.mcc208.3gppnetwork.org",
        "hss01.epc.mnc001.mcc208.3gppnetwork.org",
        "epc.mnc001.mcc208.3gppnetwork.org",
        "999000111222333",
        0,
        None,
    );
    let noa_unreg = hss.process_nor(&nor_unreg);
    assert_eq!(noa_unreg.result_code(), Some(RESULT_CODE_USER_UNKNOWN));

    assert_eq!(hss.total_nor_received, 2);
    assert_eq!(hss.total_nor_accepted, 1);
    assert_eq!(hss.total_nor_rejected, 1);
}

use toy_tcpip::diameter_sgd::{
    DIAMETER_APPLICATION_SGD, DIAMETER_CMD_MO_FORWARD_SM, DIAMETER_CMD_MT_FORWARD_SM, SgdAvp,
    SgdMessage, SmDeliveryOutcome, SmsSgdEngine,
};

#[test]
fn test_diameter_sgd_mo_and_mt_sms_routing() {
    let mut smsc = SmsSgdEngine::new("+886900000000");

    // 1. Mobile-Originated (MO) SMS
    let ofr = SgdMessage::new_ofr(
        "sgd-sess-mo-1",
        "460021234567890",
        "+886900000000",
        b"SMS over LTE Message".to_vec(),
    );
    assert_eq!(ofr.application_id, DIAMETER_APPLICATION_SGD);
    assert_eq!(ofr.command_code, DIAMETER_CMD_MO_FORWARD_SM);

    let ofa = smsc.handle_mo_forward_sm(&ofr);
    assert!(!ofa.is_request);
    let rc = ofa.avps.iter().find_map(|a| {
        if let SgdAvp::ResultCode(c) = a {
            Some(*c)
        } else {
            None
        }
    });
    assert_eq!(rc, Some(2001));
    assert_eq!(smsc.total_mo_sms, 1);

    // 2. Mobile-Terminated (MT) SMS
    let tfr = SgdMessage::new_tfr(
        "sgd-sess-mt-1",
        "460021234567890",
        "+886900000000",
        b"SMS Trigger Notification".to_vec(),
    );
    assert_eq!(tfr.command_code, DIAMETER_CMD_MT_FORWARD_SM);

    let tfa = smsc.handle_mt_forward_sm(&tfr, true);
    let outcome = tfa.avps.iter().find_map(|a| {
        if let SgdAvp::SmDeliveryOutcome(o) = a {
            Some(*o)
        } else {
            None
        }
    });
    assert_eq!(outcome, Some(SmDeliveryOutcome::Success));
    assert_eq!(smsc.total_mt_sms, 1);
}

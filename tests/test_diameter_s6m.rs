use toy_tcpip::diameter_s6m::{
    DIAMETER_APPLICATION_S6M, DIAMETER_CMD_SUBSCRIBER_INFORMATION, S6mAvp, S6mHssEngine,
    S6mMessage, SmsMiResult,
};

#[test]
fn test_diameter_s6m_sms_authorization() {
    let mut hss = S6mHssEngine::new("hss.carrier.net");
    hss.register_subscriber("460029988776655", SmsMiResult::Authorized);

    let req = S6mMessage::new_sir("s6m-sess-001", "460029988776655");
    assert_eq!(req.application_id, DIAMETER_APPLICATION_S6M);
    assert_eq!(req.command_code, DIAMETER_CMD_SUBSCRIBER_INFORMATION);

    let resp = hss.handle_sir(&req);
    let rc = resp.avps.iter().find_map(|a| {
        if let S6mAvp::ResultCode(c) = a {
            Some(*c)
        } else {
            None
        }
    });
    assert_eq!(rc, Some(2001));

    let auth = resp.avps.iter().find_map(|a| {
        if let S6mAvp::SmsMiResult(r) = a {
            Some(*r)
        } else {
            None
        }
    });
    assert_eq!(auth, Some(SmsMiResult::Authorized));
}

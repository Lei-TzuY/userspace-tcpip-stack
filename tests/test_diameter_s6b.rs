use toy_tcpip::diameter_s6b::{
    AaaS6bEngine, Non3gppSubProfile, Non3gppUserStatus, S6bAvp, S6bMessage,
    DIAMETER_APPLICATION_S6B, DIAMETER_CMD_AA, DIAMETER_CMD_SESSION_TERMINATION,
};

#[test]
fn test_diameter_s6b_aar_aaa_non_3gpp_auth() {
    let mut aaa = AaaS6bEngine::new("aaa01.vowifi.operator.com");
    aaa.provision_subscriber(Non3gppSubProfile {
        imsi: "310260000000001".into(),
        authorized_anid: vec!["WLAN".into(), "HRPD".into()],
        allocated_pgw_ip: [198, 51, 100, 1],
        allocated_pgw_fqdn: "pgw01.epc.operator.com".into(),
        apn: "ims.vowifi".into(),
        status: Non3gppUserStatus::UserDeregistered,
    });

    let mut aar = S6bMessage::new_request(DIAMETER_CMD_AA, "s6b-sess-101");
    aar.add_avp(S6bAvp::UserName("310260000000001".into()));
    aar.add_avp(S6bAvp::Anid("WLAN".into()));

    let aaa_resp = aaa.handle_aar(&aar);
    assert_eq!(aaa_resp.application_id, DIAMETER_APPLICATION_S6B);
    assert_eq!(aaa_resp.command_code, DIAMETER_CMD_AA);
    assert!(!aaa_resp.is_request);

    // Verify Result-Code 2001 (DIAMETER_SUCCESS)
    let rc = aaa_resp.avps.iter().find_map(|a| if let S6bAvp::ResultCode(c) = a { Some(*c) } else { None });
    assert_eq!(rc, Some(2001));

    // Verify MIP6-Agent-Info returned
    let mip6 = aaa_resp.avps.iter().find_map(|a| if let S6bAvp::Mip6AgentInfo(info) = a { Some(info.clone()) } else { None });
    assert!(mip6.is_some());
    let info = mip6.unwrap();
    assert_eq!(info.pgw_ip, [198, 51, 100, 1]);
    assert_eq!(info.pgw_fqdn, "pgw01.epc.operator.com");

    // Verify Subscriber status is now Active
    let sub = aaa.subscribers.get("310260000000001").unwrap();
    assert_eq!(sub.status, Non3gppUserStatus::UserActive);
}

#[test]
fn test_diameter_s6b_anid_unauthorized_rejection() {
    let mut aaa = AaaS6bEngine::new("aaa01.vowifi.operator.com");
    aaa.provision_subscriber(Non3gppSubProfile {
        imsi: "310260000000002".into(),
        authorized_anid: vec!["WLAN".into()],
        allocated_pgw_ip: [198, 51, 100, 2],
        allocated_pgw_fqdn: "pgw02.epc.operator.com".into(),
        apn: "internet".into(),
        status: Non3gppUserStatus::UserDeregistered,
    });

    let mut aar = S6bMessage::new_request(DIAMETER_CMD_AA, "s6b-sess-102");
    aar.add_avp(S6bAvp::UserName("310260000000002".into()));
    aar.add_avp(S6bAvp::Anid("WIMAX".into())); // Unauthorized ANID

    let aaa_resp = aaa.handle_aar(&aar);
    let rc = aaa_resp.avps.iter().find_map(|a| if let S6bAvp::ResultCode(c) = a { Some(*c) } else { None });
    assert_eq!(rc, Some(5003)); // DIAMETER_AUTHORIZATION_REJECTED
}

#[test]
fn test_diameter_s6b_session_termination_lifecycle() {
    let mut aaa = AaaS6bEngine::new("aaa01.vowifi.operator.com");
    aaa.provision_subscriber(Non3gppSubProfile {
        imsi: "310260000000003".into(),
        authorized_anid: vec!["WLAN".into()],
        allocated_pgw_ip: [198, 51, 100, 3],
        allocated_pgw_fqdn: "pgw03".into(),
        apn: "ims".into(),
        status: Non3gppUserStatus::UserDeregistered,
    });

    let mut aar = S6bMessage::new_request(DIAMETER_CMD_AA, "s6b-sess-103");
    aar.add_avp(S6bAvp::UserName("310260000000003".into()));
    aar.add_avp(S6bAvp::Anid("WLAN".into()));
    aaa.handle_aar(&aar);

    assert_eq!(aaa.active_sessions.len(), 1);

    // Send STR
    let str_msg = S6bMessage::new_request(DIAMETER_CMD_SESSION_TERMINATION, "s6b-sess-103");
    let sta = aaa.handle_str(&str_msg);
    let rc = sta.avps.iter().find_map(|a| if let S6bAvp::ResultCode(c) = a { Some(*c) } else { None });
    assert_eq!(rc, Some(2001));
    assert_eq!(aaa.active_sessions.len(), 0);
    assert_eq!(aaa.subscribers.get("310260000000003").unwrap().status, Non3gppUserStatus::UserDeregistered);
}

use toy_tcpip::diameter_charging::{
    CcRequestType, CreditControlRequest, DIAMETER_APPLICATION_CREDIT_CONTROL,
    DIAMETER_CMD_CREDIT_CONTROL, DIAMETER_CREDIT_LIMIT_REACHED, MsccContainer,
    OnlineChargingEngine, ServiceQuotaUnit,
};

#[test]
fn test_diameter_credit_control_request_and_mscc_codec() {
    let mut req = CreditControlRequest::new(
        "sess-ims-5g-1234",
        CcRequestType::InitialRequest,
        0,
        "imsi-208950000000001",
    );
    let mut mscc = MsccContainer::new(100);
    mscc.granted_units = Some(ServiceQuotaUnit {
        total_octets: 10_000_000,
        time_seconds: 3600,
    });
    req.mscc.push(mscc);

    let diam_msg = req.to_diameter_message(10, 20);
    assert_eq!(diam_msg.header.command_code, DIAMETER_CMD_CREDIT_CONTROL);
    assert_eq!(
        diam_msg.header.application_id,
        DIAMETER_APPLICATION_CREDIT_CONTROL
    );

    let parsed_req =
        CreditControlRequest::from_diameter_message(&diam_msg).expect("parse CCR from msg");
    assert_eq!(parsed_req.session_id, "sess-ims-5g-1234");
    assert_eq!(parsed_req.request_type, CcRequestType::InitialRequest);
    assert_eq!(parsed_req.subscriber_id, "imsi-208950000000001");
    assert_eq!(parsed_req.mscc.len(), 1);
    assert_eq!(parsed_req.mscc[0].rating_group, 100);
    assert_eq!(
        parsed_req.mscc[0].granted_units.unwrap().total_octets,
        10_000_000
    );
}

#[test]
fn test_online_charging_system_lifecycle_and_balance_exhaustion() {
    let mut ocs = OnlineChargingEngine::new(5 * 1024 * 1024); // 5 MB grant quota
    let sub = "imsi-208950000000001";
    ocs.provision_subscriber(sub, 12 * 1024 * 1024); // 12 MB initial balance

    // 1. Initial Request
    let mut init_req =
        CreditControlRequest::new("session-01", CcRequestType::InitialRequest, 0, sub);
    init_req.mscc.push(MsccContainer::new(200));
    let init_resp = ocs.process_ccr(&init_req);
    assert_eq!(init_resp.get_avp(268).unwrap().as_u32().unwrap(), 2001); // DIAMETER_SUCCESS

    let acc = ocs.accounts.get(sub).unwrap();
    assert_eq!(acc.granted_reserved_octets, 5 * 1024 * 1024);
    assert_eq!(acc.consumed_octets, 0);

    // 2. Update Request consuming 5 MB and requesting next quota
    let mut update_req1 =
        CreditControlRequest::new("session-01", CcRequestType::UpdateRequest, 1, sub);
    let mut mscc1 = MsccContainer::new(200);
    mscc1.used_units = Some(ServiceQuotaUnit {
        total_octets: 5 * 1024 * 1024,
        time_seconds: 60,
    });
    update_req1.mscc.push(mscc1);
    let update_resp1 = ocs.process_ccr(&update_req1);
    assert_eq!(update_resp1.get_avp(268).unwrap().as_u32().unwrap(), 2001);

    let acc = ocs.accounts.get(sub).unwrap();
    assert_eq!(acc.consumed_octets, 5 * 1024 * 1024);
    assert_eq!(acc.total_balance_octets, 7 * 1024 * 1024); // 12 - 5 = 7 MB remaining

    // 3. Update Request consuming 5 MB -> 2 MB remaining
    let mut update_req2 =
        CreditControlRequest::new("session-01", CcRequestType::UpdateRequest, 2, sub);
    let mut mscc2 = MsccContainer::new(200);
    mscc2.used_units = Some(ServiceQuotaUnit {
        total_octets: 5 * 1024 * 1024,
        time_seconds: 60,
    });
    update_req2.mscc.push(mscc2);
    let update_resp2 = ocs.process_ccr(&update_req2);
    assert_eq!(update_resp2.get_avp(268).unwrap().as_u32().unwrap(), 2001);

    let acc = ocs.accounts.get(sub).unwrap();
    assert_eq!(acc.consumed_octets, 10 * 1024 * 1024);
    assert_eq!(acc.total_balance_octets, 2 * 1024 * 1024); // 2 MB remaining

    // 4. Update Request consuming remaining 2 MB -> balance exhausted!
    let mut update_req3 =
        CreditControlRequest::new("session-01", CcRequestType::UpdateRequest, 3, sub);
    let mut mscc3 = MsccContainer::new(200);
    mscc3.used_units = Some(ServiceQuotaUnit {
        total_octets: 2 * 1024 * 1024,
        time_seconds: 30,
    });
    update_req3.mscc.push(mscc3);
    let update_resp3 = ocs.process_ccr(&update_req3);
    // Find MSCC result code -> should be CREDIT_LIMIT_REACHED (4012)
    let mscc_avp = update_resp3
        .avps
        .iter()
        .find(|a| a.code == toy_tcpip::diameter_charging::AVP_MULTIPLE_SERVICES_CREDIT_CONTROL)
        .unwrap();
    let parsed_mscc = MsccContainer::parse_avp(mscc_avp).unwrap();
    assert_eq!(parsed_mscc.result_code, DIAMETER_CREDIT_LIMIT_REACHED);

    // 5. Termination Request
    let term_req =
        CreditControlRequest::new("session-01", CcRequestType::TerminationRequest, 4, sub);
    let term_resp = ocs.process_ccr(&term_req);
    assert_eq!(term_resp.get_avp(268).unwrap().as_u32().unwrap(), 2001);

    let acc = ocs.accounts.get(sub).unwrap();
    assert_eq!(acc.active_session, None);
    assert_eq!(acc.granted_reserved_octets, 0);
}

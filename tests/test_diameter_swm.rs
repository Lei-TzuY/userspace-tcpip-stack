use toy_tcpip::diameter_swm::{
    AaaSwmEngine, DIAMETER_APPLICATION_SWM, DIAMETER_CMD_EAP, SwmAvp, SwmMessage,
};

#[test]
fn test_diameter_swm_eap_aka_prime_handshake() {
    let mut aaa = AaaSwmEngine::new("aaa.vowifi.operator.com");
    aaa.provision_subscriber("460010000000001", vec![0x11, 0x22, 0x33, 0x44, 0x55]);

    // EAP-Response/AKA' message from ePDG
    let eap_resp = vec![
        0x02, 0x01, 0x00, 0x10, 0x32, 0x00, 0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
        0x01,
    ];
    let der = SwmMessage::new_der("swm-sess-46001", "460010000000001", "WLAN", eap_resp);

    assert_eq!(der.application_id, DIAMETER_APPLICATION_SWM);
    assert_eq!(der.command_code, DIAMETER_CMD_EAP);
    assert!(der.is_request);

    let dea = aaa.handle_der(&der);
    assert!(!dea.is_request);

    // Verify Result-Code 2001 (DIAMETER_SUCCESS)
    let rc = dea.avps.iter().find_map(|a| {
        if let SwmAvp::ResultCode(c) = a {
            Some(*c)
        } else {
            None
        }
    });
    assert_eq!(rc, Some(2001));

    // Verify MSK key of 64 bytes is returned
    let msk = dea.avps.iter().find_map(|a| {
        if let SwmAvp::EapMasterSessionKey(k) = a {
            Some(k.clone())
        } else {
            None
        }
    });
    assert!(msk.is_some());
    assert_eq!(msk.unwrap().len(), 64);

    assert_eq!(aaa.successful_authentications, 1);
    assert_eq!(aaa.active_sessions.len(), 1);
}

#[test]
fn test_diameter_swm_eap_rejection() {
    let mut aaa = AaaSwmEngine::new("aaa.vowifi.operator.com");
    aaa.provision_subscriber("460010000000002", vec![0x99; 8]);

    // Malformed/Non-Response EAP packet (e.g. type 0x04)
    let der = SwmMessage::new_der(
        "swm-sess-46002",
        "460010000000002",
        "WLAN",
        vec![0x04, 0x01, 0x00, 0x04],
    );
    let dea = aaa.handle_der(&der);

    let rc = dea.avps.iter().find_map(|a| {
        if let SwmAvp::ResultCode(c) = a {
            Some(*c)
        } else {
            None
        }
    });
    assert_eq!(rc, Some(5003)); // DIAMETER_AUTHORIZATION_REJECTED
    assert_eq!(aaa.failed_authentications, 1);
}

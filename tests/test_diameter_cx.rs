use toy_tcpip::diameter_cx::{
    CxAvp, CxMessage, HssCxEngine, ImsSub,
    CMD_UAR, CMD_MAR, CMD_SAR, DIAMETER_APP_CX,
    UserAuthorizationType, ServerAssignmentType,
};

#[test]
fn test_diameter_cx_uar_known_subscriber() {
    let mut hss = HssCxEngine::new();
    hss.add_subscriber(ImsSub {
        public_identity: "sip:alice@ims.example.com".into(),
        private_identity: "alice@ims.example.com".into(),
        assigned_scscf: Some("sip:scscf1.ims.example.com".into()),
        auth_scheme: "Digest-AKAv1-MD5".into(),
        auth_key: vec![0xAA; 16],
    });

    let mut uar = CxMessage::new_request(CMD_UAR, "cx-sess-001");
    uar.add_avp(CxAvp::PublicIdentity("sip:alice@ims.example.com".into()));
    uar.add_avp(CxAvp::UserAuthorizationType(UserAuthorizationType::Registration));

    let uaa = hss.process_uar(&uar);
    assert!(!uaa.is_request);
    assert_eq!(uaa.application_id, DIAMETER_APP_CX);

    // Should contain the assigned S-CSCF server name
    let srv = uaa.avps.iter().find_map(|a| {
        if let CxAvp::ServerName(s) = a { Some(s.clone()) } else { None }
    });
    assert_eq!(srv, Some("sip:scscf1.ims.example.com".into()));
}

#[test]
fn test_diameter_cx_uar_unknown_subscriber() {
    let mut hss = HssCxEngine::new();

    let mut uar = CxMessage::new_request(CMD_UAR, "cx-sess-002");
    uar.add_avp(CxAvp::PublicIdentity("sip:unknown@ims.example.com".into()));

    let uaa = hss.process_uar(&uar);
    // Should contain DIAMETER_ERROR_USER_UNKNOWN (5001)
    let rc = uaa.avps.iter().find_map(|a| {
        if let CxAvp::ResultCode(c) = a { Some(*c) } else { None }
    });
    assert_eq!(rc, Some(5001));
}

#[test]
fn test_diameter_cx_mar_auth_vector_retrieval() {
    let mut hss = HssCxEngine::new();
    hss.add_subscriber(ImsSub {
        public_identity: "sip:bob@ims.example.com".into(),
        private_identity: "bob@ims.example.com".into(),
        assigned_scscf: None,
        auth_scheme: "Digest-AKAv1-MD5".into(),
        auth_key: vec![0xBB; 32],
    });

    let mut mar = CxMessage::new_request(CMD_MAR, "cx-sess-003");
    mar.add_avp(CxAvp::PublicIdentity("sip:bob@ims.example.com".into()));

    let maa = hss.process_mar(&mar);
    let auth_item = maa.avps.iter().find_map(|a| {
        if let CxAvp::SipAuthDataItem { auth_scheme, auth_data } = a {
            Some((auth_scheme.clone(), auth_data.clone()))
        } else {
            None
        }
    });
    assert!(auth_item.is_some());
    let (scheme, key) = auth_item.unwrap();
    assert_eq!(scheme, "Digest-AKAv1-MD5");
    assert_eq!(key.len(), 32);

    // Verify SIP-Number-Auth-Items AVP is present
    let count = maa.avps.iter().find_map(|a| {
        if let CxAvp::SipNumberAuthItems(n) = a { Some(*n) } else { None }
    });
    assert_eq!(count, Some(1));
}

#[test]
fn test_diameter_cx_sar_assigns_scscf() {
    let mut hss = HssCxEngine::new();
    hss.add_subscriber(ImsSub {
        public_identity: "sip:carol@ims.example.com".into(),
        private_identity: "carol@ims.example.com".into(),
        assigned_scscf: None,
        auth_scheme: "Digest-AKAv1-MD5".into(),
        auth_key: vec![0xCC; 16],
    });

    // No S-CSCF assigned yet
    let sub = hss.subscribers.get("sip:carol@ims.example.com").unwrap();
    assert!(sub.assigned_scscf.is_none());

    let mut sar = CxMessage::new_request(CMD_SAR, "cx-sess-004");
    sar.add_avp(CxAvp::PublicIdentity("sip:carol@ims.example.com".into()));
    sar.add_avp(CxAvp::ServerName("sip:scscf3.ims.example.com".into()));
    sar.add_avp(CxAvp::ServerAssignmentType(ServerAssignmentType::Registration));

    let saa = hss.process_sar(&sar);
    let srv = saa.avps.iter().find_map(|a| {
        if let CxAvp::ServerName(s) = a { Some(s.clone()) } else { None }
    });
    assert_eq!(srv, Some("sip:scscf3.ims.example.com".into()));

    // Verify HSS recorded the assignment
    let sub = hss.subscribers.get("sip:carol@ims.example.com").unwrap();
    assert_eq!(sub.assigned_scscf, Some("sip:scscf3.ims.example.com".into()));
}

#[test]
fn test_diameter_cx_message_serialization() {
    let mut msg = CxMessage::new_request(CMD_UAR, "test-session");
    msg.add_avp(CxAvp::PublicIdentity("sip:test@ims.example.com".into()));
    msg.add_avp(CxAvp::UserAuthorizationType(UserAuthorizationType::Registration));

    let wire = msg.serialize();
    // Verify basic structure: 4B cmd + 1B flags + 4B app + 4B h2h + 4B e2e + session + avps
    assert!(wire.len() > 17);
    assert_eq!(wire[4], 0x80); // Request flag
    let app_id = u32::from_be_bytes([wire[5], wire[6], wire[7], wire[8]]);
    assert_eq!(app_id, DIAMETER_APP_CX);
}

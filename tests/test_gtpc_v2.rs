use toy_tcpip::gtpc_v2::{
    CAUSE_REQUEST_ACCEPTED, GTPV2C_CREATE_SESSION_REQ, GTPV2C_CREATE_SESSION_RSP, Gtpv2cMessage,
    IE_APN, IE_CAUSE, IE_FTEID, IE_IMSI, SgwEngine, decode_imsi_tbcd, encode_imsi_tbcd,
};

#[test]
fn test_imsi_tbcd_encoding_roundtrip() {
    let cases = vec!["310260123456789", "46001234567890", "001010123456789"];
    for imsi in cases {
        let encoded = encode_imsi_tbcd(imsi);
        let decoded = decode_imsi_tbcd(&encoded);
        assert_eq!(decoded, imsi, "TBCD roundtrip failed for {}", imsi);
    }
}

#[test]
fn test_gtpv2c_create_session_request_response_flow() {
    let req = Gtpv2cMessage::create_session_request(
        0,                                 // TEID
        42,                                // Sequence
        "310260987654321",                 // IMSI
        "lte.internet.mnc260.mcc310.gprs", // APN
        0x0001,                            // MME F-TEID
        [10, 0, 0, 100],                   // MME IP
        5,                                 // Default EBI
    );

    assert_eq!(req.header.msg_type, GTPV2C_CREATE_SESSION_REQ);
    assert_eq!(req.header.version, 2);
    assert!(req.header.teid_flag);

    // Verify IEs present
    assert!(req.find_ie(IE_IMSI).is_some());
    assert!(req.find_ie(IE_APN).is_some());
    assert!(req.find_ie(IE_FTEID).is_some());

    // SGW processes the request
    let mut sgw = SgwEngine::new();
    let rsp = sgw.process_create_session(&req);
    assert_eq!(rsp.header.msg_type, GTPV2C_CREATE_SESSION_RSP);
    assert_eq!(rsp.header.sequence, 42); // Same sequence as request

    // Check Cause = Request Accepted
    let cause_ie = rsp.find_ie(IE_CAUSE).unwrap();
    assert_eq!(cause_ie.data[0], CAUSE_REQUEST_ACCEPTED);

    // Check SGW F-TEID assigned
    let fteid_ie = rsp.find_ie(IE_FTEID).unwrap();
    assert!(fteid_ie.data.len() >= 9);

    // Verify session stored
    assert_eq!(sgw.sessions.len(), 1);
    assert_eq!(sgw.sessions[0].imsi, "310260987654321");
    assert!(sgw.sessions[0].apn.contains("lte"));
}

#[test]
fn test_gtpv2c_message_serialize_parse_roundtrip() {
    let req = Gtpv2cMessage::create_session_request(
        0xABCD1234,
        0x00FFEE,
        "46001234567890",
        "internet",
        0x5678,
        [192, 168, 1, 1],
        5,
    );

    let wire = req.serialize();
    let parsed = Gtpv2cMessage::parse(&wire).unwrap();

    assert_eq!(parsed.header.version, 2);
    assert_eq!(parsed.header.msg_type, GTPV2C_CREATE_SESSION_REQ);
    assert_eq!(parsed.header.teid, 0xABCD1234);
    assert_eq!(parsed.header.sequence, 0x00FFEE);
    assert_eq!(parsed.ies.len(), req.ies.len());

    // Each IE should match
    for (orig, parsed_ie) in req.ies.iter().zip(parsed.ies.iter()) {
        assert_eq!(orig.ie_type, parsed_ie.ie_type);
        assert_eq!(orig.data, parsed_ie.data);
    }
}

#[test]
fn test_sgw_multi_session_teid_allocation() {
    let mut sgw = SgwEngine::new();

    for i in 0u32..5 {
        let req = Gtpv2cMessage::create_session_request(
            0,
            i,
            &format!("31026000000000{}", i),
            "internet",
            i + 1,
            [10, 0, 0, 1],
            5,
        );
        let rsp = sgw.process_create_session(&req);
        assert_eq!(rsp.header.msg_type, GTPV2C_CREATE_SESSION_RSP);
    }

    assert_eq!(sgw.sessions.len(), 5);
    // Verify TEIDs are unique and monotonically increasing
    let teids: Vec<u32> = sgw.sessions.iter().map(|s| s.sgw_teid).collect();
    for i in 1..teids.len() {
        assert!(teids[i] > teids[i - 1]);
    }
}

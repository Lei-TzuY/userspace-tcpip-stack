//! Integration tests for 3GPP TS 23.501 / TS 23.502 / TS 29.244 5G I-UPF & Uplink Classifier (ULCL).

use toy_tcpip::iupf_5g::*;

// Helper to build a minimal IPv4 packet (20-byte header + data)
fn make_mock_ipv4_packet(dest_ip: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut ip = vec![0u8; 20 + payload.len()];
    ip[0] = 0x45; // IPv4, 20-byte header
    let total_len = (20 + payload.len()) as u16;
    ip[2..4].copy_from_slice(&total_len.to_be_bytes());
    ip[12..16].copy_from_slice(&[192, 168, 1, 10]); // Source IP
    ip[16..20].copy_from_slice(&dest_ip); // Dest IP
    ip[20..].copy_from_slice(payload);
    ip
}

// Helper to wrap IP packet into N3 GTP-U packet
fn wrap_n3_gtp(teid: u32, ip_pkt: &[u8]) -> Vec<u8> {
    let mut gtp = Vec::with_capacity(8 + ip_pkt.len());
    gtp.push(0x30); // GTPv1 G-PDU
    gtp.push(0xFF);
    gtp.extend_from_slice(&(ip_pkt.len() as u16).to_be_bytes());
    gtp.extend_from_slice(&teid.to_be_bytes());
    gtp.extend_from_slice(ip_pkt);
    gtp
}

// ---------------------------------------------------------------------------
// 1. ULCL Local Edge Steering Happy Path
// ---------------------------------------------------------------------------

#[test]
fn test_iupf_ulcl_local_edge_steering_happy_path() {
    let mut iupf = IUpfEngine::new("iupf-edge-datacenter-01");

    let sess_id = "sess-ue-01";
    let n3_teid = 0x10000001;
    let gnb_dl_teid = 0x20000001;

    let central_target = RoutingTarget::CentralInternetPsa {
        n9_teid: 0x90000001,
        central_upf_ip: [10, 0, 0, 1],
    };

    iupf.create_session(
        sess_id,
        [192, 168, 1, 10],
        n3_teid,
        gnb_dl_teid,
        central_target,
    );

    // Add ULCL rule: Subnet 10.200.0.0/16 steers to Local Edge PSA
    let edge_target = RoutingTarget::LocalEdgePsa {
        n9_teid: 0x80000001,
        edge_upf_ip: [10, 200, 0, 1],
    };

    let rule = UlclFilterRule {
        rule_id: 1,
        dest_ip_prefix: [10, 200, 0, 0],
        dest_ip_mask: [255, 255, 0, 0],
        target: edge_target.clone(),
    };
    iupf.add_ulcl_rule(sess_id, rule).unwrap();

    // Packet 1: To Local Edge (10.200.15.8)
    let ip_pkt1 = make_mock_ipv4_packet([10, 200, 15, 8], b"MEC Video Stream Request");
    let n3_gtp1 = wrap_n3_gtp(n3_teid, &ip_pkt1);

    let res1 = iupf.process_uplink_n3_packet(&n3_gtp1).unwrap();
    assert_eq!(res1.target, edge_target);
    // Verify N9 TEID is 0x80000001
    let n9_teid1 = u32::from_be_bytes([
        res1.gtp_packet[4],
        res1.gtp_packet[5],
        res1.gtp_packet[6],
        res1.gtp_packet[7],
    ]);
    assert_eq!(n9_teid1, 0x80000001);

    // Packet 2: To General Internet (8.8.8.8)
    let ip_pkt2 = make_mock_ipv4_packet([8, 8, 8, 8], b"DNS Query");
    let n3_gtp2 = wrap_n3_gtp(n3_teid, &ip_pkt2);

    let res2 = iupf.process_uplink_n3_packet(&n3_gtp2).unwrap();
    match res2.target {
        RoutingTarget::CentralInternetPsa { n9_teid, .. } => {
            assert_eq!(n9_teid, 0x90000001);
        }
        _ => panic!("Expected CentralInternetPsa"),
    }
}

// ---------------------------------------------------------------------------
// 2. Handover Relocation Buffering and Flush
// ---------------------------------------------------------------------------

#[test]
fn test_iupf_handover_buffering_and_flush() {
    let mut iupf = IUpfEngine::new("iupf-handover-02");

    let sess_id = "sess-ue-ho";
    let n3_teid = 0x1111;
    let old_gnb_teid = 0x2222;

    iupf.create_session(
        sess_id,
        [192, 168, 1, 20],
        n3_teid,
        old_gnb_teid,
        RoutingTarget::CentralInternetPsa {
            n9_teid: 0x9999,
            central_upf_ip: [10, 0, 0, 1],
        },
    );

    // Normal downlink forwarding before handover
    let normal_dl = iupf.process_downlink_packet(sess_id, b"Normal DL").unwrap();
    assert!(normal_dl.is_some());
    let old_teid = u32::from_be_bytes([
        normal_dl.as_ref().unwrap()[4],
        normal_dl.as_ref().unwrap()[5],
        normal_dl.as_ref().unwrap()[6],
        normal_dl.as_ref().unwrap()[7],
    ]);
    assert_eq!(old_teid, old_gnb_teid);

    // Step 1: Initiate Handover -> Downlink packets must be buffered!
    iupf.initiate_handover(sess_id).unwrap();

    let dl1 = iupf
        .process_downlink_packet(sess_id, b"In-Flight Packet 1")
        .unwrap();
    assert!(dl1.is_none());
    let dl2 = iupf
        .process_downlink_packet(sess_id, b"In-Flight Packet 2")
        .unwrap();
    assert!(dl2.is_none());

    // Step 2: Handover Complete to Target gNodeB (TEID 0x3333)
    let new_gnb_teid = 0x3333;
    let flushed = iupf.complete_handover(sess_id, new_gnb_teid).unwrap();
    assert_eq!(flushed.len(), 2);

    for pkt in flushed {
        let teid = u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
        assert_eq!(teid, new_gnb_teid);
    }
}

// ---------------------------------------------------------------------------
// 3. Corrupt GTP and IP Payload Rejections
// ---------------------------------------------------------------------------

#[test]
fn test_iupf_corrupt_gtp_and_ip_payload_rejections() {
    let mut iupf = IUpfEngine::new("iupf-err-03");

    let n3_teid = 0x5555;
    iupf.create_session(
        "sess-err",
        [192, 168, 1, 30],
        n3_teid,
        0x6666,
        RoutingTarget::CentralInternetPsa {
            n9_teid: 0x7777,
            central_upf_ip: [1, 2, 3, 4],
        },
    );

    // Truncated GTP packet (< 8 bytes)
    let err1 = iupf.process_uplink_n3_packet(&[0x30, 0xFF, 0x00]);
    assert_eq!(
        err1,
        Err(IUpfError::InvalidGtpPacket(
            "GTP-U packet shorter than 8 bytes"
        ))
    );

    // GTP valid header but IP payload < 20 bytes
    let mut bad_ip = vec![0x30, 0xFF, 0x00, 0x05];
    bad_ip.extend_from_slice(&n3_teid.to_be_bytes());
    bad_ip.extend_from_slice(&[0x45, 0x00, 0x01, 0x02, 0x03]); // only 5 bytes IP
    let err2 = iupf.process_uplink_n3_packet(&bad_ip);
    assert_eq!(
        err2,
        Err(IUpfError::InvalidGtpPacket(
            "IP payload too short for IPv4 header"
        ))
    );
}

// ---------------------------------------------------------------------------
// 4. Unknown TEID Handling
// ---------------------------------------------------------------------------

#[test]
fn test_iupf_unknown_teid_handling() {
    let iupf = IUpfEngine::new("iupf-err-04");

    let ip_pkt = make_mock_ipv4_packet([8, 8, 8, 8], b"Test");
    let bad_n3 = wrap_n3_gtp(0xDEADBEEF, &ip_pkt);

    let err = iupf.process_uplink_n3_packet(&bad_n3);
    assert_eq!(err, Err(IUpfError::SessionNotFound));
}

// ---------------------------------------------------------------------------
// 5. Session Removal Lifecycle
// ---------------------------------------------------------------------------

#[test]
fn test_iupf_session_removal_lifecycle() {
    let mut iupf = IUpfEngine::new("iupf-core-05");

    let sess_id = "sess-del";
    let n3_teid = 0x8888;
    iupf.create_session(
        sess_id,
        [192, 168, 1, 50],
        n3_teid,
        0x9999,
        RoutingTarget::CentralInternetPsa {
            n9_teid: 0xAAAA,
            central_upf_ip: [1, 1, 1, 1],
        },
    );

    assert!(iupf.sessions.contains_key(sess_id));
    assert!(iupf.n3_teid_to_session.contains_key(&n3_teid));

    iupf.remove_session(sess_id).expect("Remove failed");
    assert!(!iupf.sessions.contains_key(sess_id));
    assert!(!iupf.n3_teid_to_session.contains_key(&n3_teid));

    let err = iupf.remove_session(sess_id);
    assert_eq!(err, Err(IUpfError::SessionNotFound));
}

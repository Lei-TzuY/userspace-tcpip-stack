//! Integration tests for 3GPP TS 23.247 / TS 29.581 / TS 29.244 Annex G 5G MB-UPF.

use toy_tcpip::mb_upf_5g::*;

// ---------------------------------------------------------------------------
// 1. Multicast Replication Fanout Happy Path
// ---------------------------------------------------------------------------

#[test]
fn test_mb_upf_multicast_replication_fanout_happy_path() {
    let mut mb_upf = MbUpfEngine::new("mb-upf-tokyo-stadium-01");

    let sess_id = "mbs-sess-stadium-4k";
    let tmgi = "tmgi-440-53-0001";
    let flow = MulticastFlowSpec {
        source_ip: [198, 51, 100, 10], // Broadcaster CDN
        group_ip: [232, 1, 1, 50],     // SSM Multicast Group
        port: 5004,
    };
    let shared_teid = 0x55000001;

    mb_upf.create_mbs_session(sess_id, tmgi, MbsSessionType::Multicast, flow, shared_teid);

    // Register 3 gNodeB cell tower branches in the stadium
    mb_upf
        .add_gnb_branch(sess_id, "gnb-stadium-north", [10, 1, 1, 1], 0x1001)
        .unwrap();
    mb_upf
        .add_gnb_branch(sess_id, "gnb-stadium-south", [10, 1, 1, 2], 0x1002)
        .unwrap();
    mb_upf
        .add_gnb_branch(sess_id, "gnb-stadium-east", [10, 1, 1, 3], 0x1003)
        .unwrap();

    // Ingest multicast video chunk from N6mb
    let video_frame = b"4K HDR 60fps Live Video Slice Payload";
    let replicated = mb_upf.ingest_and_replicate(sess_id, video_frame).unwrap();

    // 1 packet in -> 3 replicated packets out
    assert_eq!(replicated.len(), 3);

    for pkt in &replicated {
        assert_eq!(pkt.gtp_packet[0], 0x30); // GTPv1
        assert_eq!(pkt.gtp_packet[1], 0xFF); // G-PDU
        let parsed_len = u16::from_be_bytes([pkt.gtp_packet[2], pkt.gtp_packet[3]]);
        assert_eq!(usize::from(parsed_len), video_frame.len());
        let parsed_teid = u32::from_be_bytes([
            pkt.gtp_packet[4],
            pkt.gtp_packet[5],
            pkt.gtp_packet[6],
            pkt.gtp_packet[7],
        ]);
        match pkt.gnb_id.as_str() {
            "gnb-stadium-north" => {
                assert_eq!(parsed_teid, 0x1001);
                assert_eq!(pkt.dest_ip, [10, 1, 1, 1]);
            }
            "gnb-stadium-south" => {
                assert_eq!(parsed_teid, 0x1002);
                assert_eq!(pkt.dest_ip, [10, 1, 1, 2]);
            }
            "gnb-stadium-east" => {
                assert_eq!(parsed_teid, 0x1003);
                assert_eq!(pkt.dest_ip, [10, 1, 1, 3]);
            }
            _ => panic!("Unexpected gNodeB ID"),
        }
        assert_eq!(&pkt.gtp_packet[8..], video_frame);
    }

    let sess = mb_upf.sessions.get(sess_id).unwrap();
    assert_eq!(sess.packets_forwarded, 1);
    assert_eq!(sess.bytes_forwarded, (video_frame.len() * 3) as u64);
}

// ---------------------------------------------------------------------------
// 2. Dynamic Branch Addition and Removal
// ---------------------------------------------------------------------------

#[test]
fn test_mb_upf_dynamic_branch_addition_and_removal() {
    let mut mb_upf = MbUpfEngine::new("mb-upf-dynamic-02");

    let sess_id = "mbs-sess-ota";
    let flow = MulticastFlowSpec {
        source_ip: [192, 0, 2, 1],
        group_ip: [232, 2, 2, 2],
        port: 8080,
    };

    mb_upf.create_mbs_session(
        sess_id,
        "tmgi-ota-01",
        MbsSessionType::Multicast,
        flow,
        0x9999,
    );

    mb_upf
        .add_gnb_branch(sess_id, "gnb-cell-1", [10, 2, 1, 1], 0x2001)
        .unwrap();
    mb_upf
        .add_gnb_branch(sess_id, "gnb-cell-2", [10, 2, 1, 2], 0x2002)
        .unwrap();

    // Duplicate branch must fail
    let err1 = mb_upf.add_gnb_branch(sess_id, "gnb-cell-1", [10, 2, 1, 1], 0x2001);
    assert_eq!(err1, Err(MbUpfError::BranchAlreadyExists));

    // Remove gnb-cell-2
    mb_upf.remove_gnb_branch(sess_id, "gnb-cell-2").unwrap();

    // Removing again returns BranchNotFound
    let err2 = mb_upf.remove_gnb_branch(sess_id, "gnb-cell-2");
    assert_eq!(err2, Err(MbUpfError::BranchNotFound));

    // Next replication goes to gnb-cell-1 only
    let res = mb_upf
        .ingest_and_replicate(sess_id, b"firmware-block-1")
        .unwrap();
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].gnb_id, "gnb-cell-1");
}

// ---------------------------------------------------------------------------
// 3. Empty Payload Rejection
// ---------------------------------------------------------------------------

#[test]
fn test_mb_upf_empty_payload_rejection() {
    let mut mb_upf = MbUpfEngine::new("mb-upf-err-03");

    let sess_id = "sess-empty";
    let flow = MulticastFlowSpec {
        source_ip: [1, 2, 3, 4],
        group_ip: [232, 0, 0, 1],
        port: 1234,
    };
    mb_upf.create_mbs_session(sess_id, "tmgi-03", MbsSessionType::Broadcast, flow, 0x3333);

    let err = mb_upf.ingest_and_replicate(sess_id, b"");
    assert_eq!(err, Err(MbUpfError::EmptyPayload));
}

// ---------------------------------------------------------------------------
// 4. Session Termination Lifecycle
// ---------------------------------------------------------------------------

#[test]
fn test_mb_upf_session_termination() {
    let mut mb_upf = MbUpfEngine::new("mb-upf-term-04");

    let sess_id = "sess-term";
    let flow = MulticastFlowSpec {
        source_ip: [10, 0, 0, 1],
        group_ip: [232, 5, 5, 5],
        port: 5555,
    };
    mb_upf.create_mbs_session(
        sess_id,
        "tmgi-04",
        MbsSessionType::Multicast,
        flow.clone(),
        0x4444,
    );

    assert!(mb_upf.sessions.contains_key(sess_id));
    assert!(mb_upf.flow_to_session.contains_key(&flow));

    mb_upf
        .terminate_mbs_session(sess_id)
        .expect("Termination failed");
    assert!(!mb_upf.sessions.contains_key(sess_id));
    assert!(!mb_upf.flow_to_session.contains_key(&flow));

    let err = mb_upf.terminate_mbs_session(sess_id);
    assert_eq!(err, Err(MbUpfError::SessionNotFound));
}

// ---------------------------------------------------------------------------
// 5. Broadcast Session Multi-Tower Delivery
// ---------------------------------------------------------------------------

#[test]
fn test_mb_upf_broadcast_session_multi_tower_delivery() {
    let mut mb_upf = MbUpfEngine::new("mb-upf-broadcast-05");

    let sess_id = "sess-emergency-alert";
    let flow = MulticastFlowSpec {
        source_ip: [100, 64, 0, 1],
        group_ip: [232, 9, 9, 9], // Public warning broadcast
        port: 9999,
    };
    mb_upf.create_mbs_session(
        sess_id,
        "tmgi-emergency",
        MbsSessionType::Broadcast,
        flow,
        0x8888,
    );

    mb_upf
        .add_gnb_branch(sess_id, "tower-a", [172, 16, 0, 1], 0x8001)
        .unwrap();
    mb_upf
        .add_gnb_branch(sess_id, "tower-b", [172, 16, 0, 2], 0x8002)
        .unwrap();

    let alert_msg = b"EARTHQUAKE EARLY WARNING: Prepare for strong shaking!";
    let replicated = mb_upf.ingest_and_replicate(sess_id, alert_msg).unwrap();

    assert_eq!(replicated.len(), 2);
    for r in replicated {
        assert_eq!(&r.gtp_packet[8..], alert_msg);
    }
}

// ---------------------------------------------------------------------------
// 6. GTP-U Length Boundary and Fail-Closed Oversize Rejection
// ---------------------------------------------------------------------------

#[test]
fn test_mb_upf_gtpu_length_boundary_and_oversize_rejection() {
    let mut mb_upf = MbUpfEngine::new("mb-upf-length-06");
    let sess_id = "sess-length-boundary";
    let flow = MulticastFlowSpec {
        source_ip: [203, 0, 113, 10],
        group_ip: [232, 10, 10, 10],
        port: 5000,
    };
    mb_upf.create_mbs_session(
        sess_id,
        "tmgi-length-06",
        MbsSessionType::Multicast,
        flow,
        0x6000,
    );
    mb_upf
        .add_gnb_branch(sess_id, "gnb-length", [10, 6, 0, 1], 0x6001)
        .unwrap();

    let max_payload = vec![0xAB; usize::from(u16::MAX)];
    let replicated = mb_upf.ingest_and_replicate(sess_id, &max_payload).unwrap();
    assert_eq!(replicated.len(), 1);
    assert_eq!(
        u16::from_be_bytes([replicated[0].gtp_packet[2], replicated[0].gtp_packet[3]]),
        u16::MAX
    );
    assert_eq!(replicated[0].gtp_packet.len(), 8 + max_payload.len());

    let before = mb_upf.sessions.get(sess_id).unwrap().clone();
    let oversized_payload = vec![0xCD; usize::from(u16::MAX) + 1];
    let err = mb_upf.ingest_and_replicate(sess_id, &oversized_payload);
    assert_eq!(err, Err(MbUpfError::PayloadTooLarge));
    assert_eq!(mb_upf.sessions.get(sess_id).unwrap(), &before);
}

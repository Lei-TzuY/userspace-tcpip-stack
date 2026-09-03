//! Integration tests for 3GPP TS 29.244 PFCP Advanced UPF Packet Processing Pipeline.

use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::pfcp_5g::{
    PFCP_APPLY_ACTION_BUFF, PFCP_APPLY_ACTION_FORWARD, PFCP_SRC_INTERFACE_ACCESS,
    PFCP_SRC_INTERFACE_CORE,
};
use toy_tcpip::upf_pipeline_5g::{
    GateStatus, PacketProcessingResult, UpfBar, UpfFar, UpfPdr, UpfPipeline, UpfQer, UpfSession,
    UpfUrr,
};

#[test]
fn test_upf_pipeline_uplink_forwarding_and_urr_accounting() {
    let mut pipeline = UpfPipeline::new();
    let mut session = UpfSession::new(0x1001);

    // 1. Configure PDR 1 (Access / Uplink)
    session.pdrs.insert(
        1,
        UpfPdr {
            pdr_id: 1,
            precedence: 10,
            source_interface: PFCP_SRC_INTERFACE_ACCESS,
            teid: Some(0x50001),
            ue_ip: Some(Ipv4Address::new(10, 45, 0, 1)),
            far_id: 1,
            qer_ids: vec![1],
            urr_ids: vec![1],
        },
    );

    // 2. Configure FAR 1 (Forward to Data Network - raw IP egress)
    session.fars.insert(
        1,
        UpfFar {
            far_id: 1,
            apply_action: PFCP_APPLY_ACTION_FORWARD,
            destination_interface: 1,
            outer_header_creation: None,
            bar_id: None,
        },
    );

    // 3. Configure QER 1 (QFI 9, Gates Open)
    session.qers.insert(1, UpfQer::new(1, 9));

    // 4. Configure URR 1 (Volume Threshold 1,000 bytes)
    session.urrs.insert(1, UpfUrr::new(1, Some(1000)));

    pipeline.add_session(session);

    // 5. Ingress 1st packet: 400 bytes
    let payload1 = vec![0xAA; 400];
    let res1 = pipeline.process_ingress_packet(
        PFCP_SRC_INTERFACE_ACCESS,
        Some(0x50001),
        Some(Ipv4Address::new(10, 45, 0, 1)),
        &payload1,
        1000,
    );

    match res1 {
        PacketProcessingResult::Forwarded {
            dst_ip,
            outer_header_teid,
            qfi,
            payload,
        } => {
            assert_eq!(dst_ip, Ipv4Address::new(10, 45, 0, 1));
            assert_eq!(outer_header_teid, None);
            assert_eq!(qfi, 9);
            assert_eq!(payload.len(), 400);
        }
        _ => panic!("Expected Forwarded result"),
    }

    assert!(pipeline.collect_usage_reports(0x1001).is_empty());

    // 6. Ingress 2nd packet: 700 bytes (exceeds 1000 threshold!)
    let payload2 = vec![0xBB; 700];
    let res2 = pipeline.process_ingress_packet(
        PFCP_SRC_INTERFACE_ACCESS,
        Some(0x50001),
        Some(Ipv4Address::new(10, 45, 0, 1)),
        &payload2,
        1050,
    );

    assert!(matches!(res2, PacketProcessingResult::Forwarded { .. }));

    // 7. Verify URR Report generation
    let reports = pipeline.collect_usage_reports(0x1001);
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].urr_id, 1);
    assert_eq!(reports[0].ul_bytes, 1100);
    assert_eq!(reports[0].ul_packets, 2);
    assert_eq!(reports[0].trigger, "VolumeThreshold");
}

#[test]
fn test_upf_pipeline_downlink_buffering_and_ddn_notification() {
    let mut pipeline = UpfPipeline::new();
    let mut session = UpfSession::new(0x1002);
    let ue_ip = Ipv4Address::new(10, 45, 0, 2);

    // 1. Configure PDR 2 (Core / Downlink)
    session.pdrs.insert(
        2,
        UpfPdr {
            pdr_id: 2,
            precedence: 10,
            source_interface: PFCP_SRC_INTERFACE_CORE,
            teid: None,
            ue_ip: Some(ue_ip),
            far_id: 2,
            qer_ids: Vec::new(),
            urr_ids: Vec::new(),
        },
    );

    // 2. Configure FAR 2 (Buffering for CM-IDLE UE)
    session.fars.insert(
        2,
        UpfFar {
            far_id: 2,
            apply_action: PFCP_APPLY_ACTION_BUFF,
            destination_interface: 0,
            outer_header_creation: None,
            bar_id: Some(10),
        },
    );

    // 3. Configure BAR 10
    session.bars.insert(10, UpfBar::new(10, 5));
    pipeline.add_session(session);

    // 4. Ingress 1st DL packet -> Triggers DDN!
    let res1 = pipeline.process_ingress_packet(
        PFCP_SRC_INTERFACE_CORE,
        None,
        Some(ue_ip),
        &[1, 2, 3, 4],
        2000,
    );
    assert_eq!(
        res1,
        PacketProcessingResult::Buffered {
            bar_id: 10,
            ddn_triggered: true,
        }
    );

    // 5. Ingress 2nd DL packet -> Buffered, but DDN already sent
    let res2 = pipeline.process_ingress_packet(
        PFCP_SRC_INTERFACE_CORE,
        None,
        Some(ue_ip),
        &[5, 6, 7, 8],
        2010,
    );
    assert_eq!(
        res2,
        PacketProcessingResult::Buffered {
            bar_id: 10,
            ddn_triggered: false,
        }
    );

    // 6. UE establishes connection: update FAR to FORWARD with gNodeB GTP-U outer header
    let session_ref = pipeline.sessions.get_mut(&0x1002).unwrap();
    session_ref.fars.insert(
        2,
        UpfFar {
            far_id: 2,
            apply_action: PFCP_APPLY_ACTION_FORWARD,
            destination_interface: 0,
            outer_header_creation: Some((0x60001, Ipv4Address::new(192, 168, 1, 10))),
            bar_id: None,
        },
    );

    // 7. Flush buffer
    let flushed = pipeline.flush_buffered_packets(0x1002, 10);
    assert_eq!(flushed.len(), 2);
    match &flushed[0] {
        PacketProcessingResult::Forwarded {
            dst_ip,
            outer_header_teid,
            payload,
            ..
        } => {
            assert_eq!(*dst_ip, Ipv4Address::new(192, 168, 1, 10));
            assert_eq!(*outer_header_teid, Some(0x60001));
            assert_eq!(payload, &[1, 2, 3, 4]);
        }
        _ => panic!("Expected flushed packet forwarded"),
    }
}

#[test]
fn test_upf_pipeline_qer_gate_closed() {
    let mut pipeline = UpfPipeline::new();
    let mut session = UpfSession::new(0x1003);

    session.pdrs.insert(
        1,
        UpfPdr {
            pdr_id: 1,
            precedence: 10,
            source_interface: PFCP_SRC_INTERFACE_ACCESS,
            teid: Some(0x50003),
            ue_ip: None,
            far_id: 1,
            qer_ids: vec![1],
            urr_ids: Vec::new(),
        },
    );

    session.fars.insert(
        1,
        UpfFar {
            far_id: 1,
            apply_action: PFCP_APPLY_ACTION_FORWARD,
            destination_interface: 1,
            outer_header_creation: None,
            bar_id: None,
        },
    );

    let mut qer = UpfQer::new(1, 1);
    qer.gate_status_ul = GateStatus::Closed; // Block UL traffic
    session.qers.insert(1, qer);

    pipeline.add_session(session);

    let res = pipeline.process_ingress_packet(
        PFCP_SRC_INTERFACE_ACCESS,
        Some(0x50003),
        None,
        &[0xEE; 100],
        3000,
    );

    assert_eq!(
        res,
        PacketProcessingResult::Dropped {
            reason: "QER UL gate is closed"
        }
    );
}

#[test]
fn test_upf_pipeline_token_bucket_policer_rate_limiting() {
    let mut pipeline = UpfPipeline::new();
    let mut session = UpfSession::new(0x1004);

    session.pdrs.insert(
        1,
        UpfPdr {
            pdr_id: 1,
            precedence: 10,
            source_interface: PFCP_SRC_INTERFACE_ACCESS,
            teid: Some(0x50004),
            ue_ip: None,
            far_id: 1,
            qer_ids: vec![1],
            urr_ids: Vec::new(),
        },
    );

    session.fars.insert(
        1,
        UpfFar {
            far_id: 1,
            apply_action: PFCP_APPLY_ACTION_FORWARD,
            destination_interface: 1,
            outer_header_creation: None,
            bar_id: None,
        },
    );

    // MBR 800 kbps (100,000 B/s), burst 2,000 bytes
    let mut qer = UpfQer::new(1, 5);
    qer.set_mbr(Some(800), None, 2_000);
    session.qers.insert(1, qer);

    pipeline.add_session(session);

    // 1. Send 1000 bytes at t=0ms -> Consumes 1000, 1000 remaining -> Pass
    let res1 = pipeline.process_ingress_packet(
        PFCP_SRC_INTERFACE_ACCESS,
        Some(0x50004),
        None,
        &[0xAA; 1000],
        0,
    );
    assert!(matches!(res1, PacketProcessingResult::Forwarded { .. }));

    // 2. Send 1500 bytes at t=0ms -> Only 1000 tokens available -> Drop!
    let res2 = pipeline.process_ingress_packet(
        PFCP_SRC_INTERFACE_ACCESS,
        Some(0x50004),
        None,
        &[0xBB; 1500],
        0,
    );
    assert_eq!(
        res2,
        PacketProcessingResult::Dropped {
            reason: "MBR policer rate exceeded"
        }
    );

    // 3. Advance time to t=20ms (refills 20ms * 100,000 B/s = 2,000 tokens) -> Pass!
    let res3 = pipeline.process_ingress_packet(
        PFCP_SRC_INTERFACE_ACCESS,
        Some(0x50004),
        None,
        &[0xCC; 1500],
        20,
    );
    assert!(matches!(res3, PacketProcessingResult::Forwarded { .. }));
}

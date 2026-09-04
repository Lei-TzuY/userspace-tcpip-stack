//! Integration tests for 3GPP TS 38.351 Rel-17 & Rel-18 Sidelink Relay Adaptation Protocol (SRAP).

use toy_tcpip::nr_srap_relay::{
    SRAP_DEFAULT_MAX_HOPS, SRAP_MAX_BEARER_ID, SrapBearerMapping, SrapBearerMappingTable,
    SrapControlPdu, SrapControlPduType, SrapDataHeader, SrapDataPdu, SrapEntity, SrapError,
    SrapFlowControlManager, SrapMultiHopRouter, SrapRole, SrapRouteEntry,
};

#[test]
fn test_srap_data_pdu_encoding_decoding_and_formats() {
    // 1. Standard 8-bit Local UE ID Header (TS 38.351 §6.2.2-1)
    let hdr_std = SrapDataHeader::new_standard(0x42, 5).expect("Valid standard header");
    assert_eq!(hdr_std.bearer_id, 5);
    assert_eq!(hdr_std.ue_id, 0x42);
    assert!(!hdr_std.is_extended_ue_id);
    assert_eq!(hdr_std.hop_count, None);
    assert_eq!(hdr_std.byte_len(), 2);

    let sdu = b"Hello 5G NR Rel-17 Sidelink Relay!".to_vec();
    let pdu_std = SrapDataPdu::new_with_header(hdr_std, sdu.clone());
    let encoded_std = pdu_std.encode();
    assert_eq!(encoded_std.len(), 2 + sdu.len());

    let decoded_std = SrapDataPdu::decode(&encoded_std, true).expect("Decode standard PDU");
    assert!(decoded_std.header.is_some());
    let dec_hdr = decoded_std.header.unwrap();
    assert_eq!(dec_hdr.bearer_id, 5);
    assert_eq!(dec_hdr.ue_id, 0x42);
    assert_eq!(decoded_std.payload, sdu);

    // 2. Extended 16-bit Local UE ID Header
    let hdr_ext = SrapDataHeader::new_extended(0x1234, 12).expect("Valid extended header");
    assert_eq!(hdr_ext.bearer_id, 12);
    assert_eq!(hdr_ext.ue_id, 0x1234);
    assert!(hdr_ext.is_extended_ue_id);
    assert_eq!(hdr_ext.byte_len(), 3);

    let pdu_ext = SrapDataPdu::new_with_header(hdr_ext, sdu.clone());
    let encoded_ext = pdu_ext.encode();
    assert_eq!(encoded_ext.len(), 3 + sdu.len());

    let decoded_ext = SrapDataPdu::decode(&encoded_ext, true).expect("Decode extended PDU");
    let dec_ext_hdr = decoded_ext.header.unwrap();
    assert_eq!(dec_ext_hdr.ue_id, 0x1234);
    assert_eq!(dec_ext_hdr.bearer_id, 12);
    assert_eq!(decoded_ext.payload, sdu);

    // 3. Rel-18 Multi-Hop Header with Hop Count (TS 38.351 §6.2.4)
    let hdr_mh = SrapDataHeader::new_multihop(0x0567, 8, 6).expect("Valid multihop header");
    assert_eq!(hdr_mh.ue_id, 0x0567);
    assert_eq!(hdr_mh.bearer_id, 8);
    assert_eq!(hdr_mh.hop_count, Some(6));
    assert_eq!(hdr_mh.byte_len(), 4);

    let pdu_mh = SrapDataPdu::new_with_header(hdr_mh, sdu.clone());
    let encoded_mh = pdu_mh.encode();
    assert_eq!(encoded_mh.len(), 4 + sdu.len());

    let decoded_mh = SrapDataPdu::decode(&encoded_mh, true).expect("Decode multihop PDU");
    let dec_mh_hdr = decoded_mh.header.unwrap();
    assert_eq!(dec_mh_hdr.ue_id, 0x0567);
    assert_eq!(dec_mh_hdr.bearer_id, 8);
    assert_eq!(dec_mh_hdr.hop_count, Some(6));

    // 4. Transparent Headerless Format (TS 38.351 Figure 6.2.2-2 for SRB0)
    let pdu_transparent = SrapDataPdu::new_transparent(sdu.clone());
    let encoded_trans = pdu_transparent.encode();
    assert_eq!(encoded_trans, sdu);

    let decoded_trans = SrapDataPdu::decode(&encoded_trans, false).expect("Decode transparent PDU");
    assert!(decoded_trans.header.is_none());
    assert_eq!(decoded_trans.payload, sdu);
}

#[test]
fn test_srap_control_pdu_types() {
    // 1. Flow Control Feedback (CPT = 0)
    let ctrl_fc = SrapControlPdu::FlowControlFeedback {
        ue_id: 0x08A1,
        bearer_id: 3,
        buffer_occupancy_bytes: 49152,
        credit_window_kbps: 500,
    };
    let encoded_fc = ctrl_fc.encode();
    assert_eq!(encoded_fc.len(), 10);
    assert_eq!(encoded_fc[0] & 0x80, 0); // D/C = 0 (Control PDU)

    let decoded_fc = SrapControlPdu::decode(&encoded_fc).expect("Decode FlowControlFeedback");
    match decoded_fc {
        SrapControlPdu::FlowControlFeedback {
            ue_id,
            bearer_id,
            buffer_occupancy_bytes,
            credit_window_kbps,
        } => {
            assert_eq!(ue_id, 0x08A1);
            assert_eq!(bearer_id, 3);
            assert_eq!(buffer_occupancy_bytes, 49152);
            assert_eq!(credit_window_kbps, 500);
        }
        _ => panic!("Expected FlowControlFeedback variant"),
    }

    // 2. Radio Link Failure Report (CPT = 1)
    let ctrl_rlf = SrapControlPdu::RadioLinkFailureReport {
        ue_id: 0x08A1,
        failed_rlc_channel_id: 4,
        cause_code: 0x02, // e.g. Max RLC retransmissions reached
    };
    let encoded_rlf = ctrl_rlf.encode();
    assert_eq!(encoded_rlf.len(), 5);

    let decoded_rlf = SrapControlPdu::decode(&encoded_rlf).expect("Decode RLF Report");
    match decoded_rlf {
        SrapControlPdu::RadioLinkFailureReport {
            ue_id,
            failed_rlc_channel_id,
            cause_code,
        } => {
            assert_eq!(ue_id, 0x08A1);
            assert_eq!(failed_rlc_channel_id, 4);
            assert_eq!(cause_code, 0x02);
        }
        _ => panic!("Expected RadioLinkFailureReport variant"),
    }

    // 3. Rel-18 Multi-Hop Route Echo (CPT = 2)
    let ctrl_echo = SrapControlPdu::MultiHopRouteEcho {
        originator_ue_id: 0x0111,
        sequence_num: 1042,
        hop_distance: 3,
    };
    let encoded_echo = ctrl_echo.encode();
    assert_eq!(encoded_echo.len(), 6);

    let decoded_echo = SrapControlPdu::decode(&encoded_echo).expect("Decode MultiHopRouteEcho");
    match decoded_echo {
        SrapControlPdu::MultiHopRouteEcho {
            originator_ue_id,
            sequence_num,
            hop_distance,
        } => {
            assert_eq!(originator_ue_id, 0x0111);
            assert_eq!(sequence_num, 1042);
            assert_eq!(hop_distance, 3);
        }
        _ => panic!("Expected MultiHopRouteEcho variant"),
    }

    // Test CPT enum conversion
    assert_eq!(u8::from(SrapControlPduType::FlowControlFeedback), 0);
    assert_eq!(u8::from(SrapControlPduType::RadioLinkFailureReport), 1);
    assert_eq!(u8::from(SrapControlPduType::MultiHopRouteEcho), 2);
    assert_eq!(
        SrapControlPduType::from(0),
        SrapControlPduType::FlowControlFeedback
    );
}

#[test]
fn test_end_to_end_u2n_relay_pipeline() {
    let remote_ue_id: u16 = 0x2A; // 42
    let relay_ue_id: u16 = 0x88;
    let bearer_id: u8 = 5; // DRB 5
    let sl_channel: u8 = 3;
    let uu_channel: u8 = 7;

    let mut remote_ue = SrapEntity::new(SrapRole::RemoteUe, remote_ue_id);
    let mut relay_ue = SrapEntity::new(SrapRole::RelayUe, relay_ue_id);
    let mut gnb = SrapEntity::new(SrapRole::GNodeB, 0x0001);

    // Common bearer mapping
    let mapping = SrapBearerMapping {
        ue_id: remote_ue_id,
        bearer_id,
        sl_rlc_channel_id: sl_channel,
        uu_rlc_channel_id: uu_channel,
        has_srap_header: true,
    };

    let mut standalone_table = SrapBearerMappingTable::new();
    standalone_table.add_mapping(mapping.clone());
    assert_eq!(
        standalone_table.find_uu_for_relay_ul(sl_channel, remote_ue_id, bearer_id),
        Some(uu_channel)
    );
    assert_eq!(
        standalone_table.find_sl_for_relay_dl(uu_channel, remote_ue_id, bearer_id),
        Some(sl_channel)
    );

    remote_ue.mapping_table.add_mapping(mapping.clone());
    relay_ue.mapping_table.add_mapping(mapping.clone());
    gnb.mapping_table.add_mapping(mapping);

    // =======================================================================
    // 1. Uplink: Remote UE -> Relay UE -> gNodeB
    // =======================================================================
    let original_ul_data = b"5G NR Uplink Sensor Telemetry Data".to_vec();

    // Remote UE transmits on DRB 5
    let (tx_sl_ch, sl_packet) = remote_ue
        .remote_transmit_ul(bearer_id, original_ul_data.clone())
        .expect("Remote UL transmit succeed");
    assert_eq!(tx_sl_ch, sl_channel);
    assert_eq!(remote_ue.metrics.tx_data_pdus, 1);

    // Relay UE receives on PC5 SL channel 3 and forwards to Uu channel 7
    let (tx_uu_ch, uu_packet, flow_ctrl) = relay_ue
        .relay_forward_ul(tx_sl_ch, &sl_packet)
        .expect("Relay UL forward succeed");
    assert_eq!(tx_uu_ch, uu_channel);
    assert_eq!(uu_packet, sl_packet);
    assert!(flow_ctrl.is_none()); // Buffer within normal limits
    assert_eq!(relay_ue.metrics.relayed_pdus, 1);

    // gNodeB receives on Uu channel 7 and demultiplexes
    let (rx_ue_id, rx_bearer_id, rx_payload) = gnb
        .gnb_receive_ul(tx_uu_ch, &uu_packet)
        .expect("gNodeB UL receive succeed");
    assert_eq!(rx_ue_id, remote_ue_id);
    assert_eq!(rx_bearer_id, bearer_id);
    assert_eq!(rx_payload, original_ul_data);
    assert_eq!(gnb.metrics.rx_data_pdus, 1);

    // =======================================================================
    // 2. Downlink: gNodeB -> Relay UE -> Remote UE
    // =======================================================================
    let original_dl_data = b"5G Core Downlink Actuation Command".to_vec();

    // gNodeB transmits to Remote UE on DRB 5
    let (tx_gnb_uu_ch, gnb_packet) = gnb
        .gnb_transmit_dl(remote_ue_id, bearer_id, original_dl_data.clone())
        .expect("gNodeB DL transmit succeed");
    assert_eq!(tx_gnb_uu_ch, uu_channel);
    assert_eq!(gnb.metrics.tx_data_pdus, 1);

    // Relay UE receives on Uu channel 7 and forwards to PC5 SL channel 3
    let (tx_relay_sl_ch, relay_packet) = relay_ue
        .relay_forward_dl(tx_gnb_uu_ch, &gnb_packet)
        .expect("Relay DL forward succeed");
    assert_eq!(tx_relay_sl_ch, sl_channel);
    assert_eq!(relay_packet, gnb_packet);
    assert_eq!(relay_ue.metrics.relayed_pdus, 2);

    // Remote UE receives on PC5 SL channel 3
    let (rx_remote_bearer, rx_remote_data) = remote_ue
        .remote_receive_dl(tx_relay_sl_ch, &relay_packet)
        .expect("Remote DL receive succeed");
    assert_eq!(rx_remote_bearer, bearer_id);
    assert_eq!(rx_remote_data, original_dl_data);
    assert_eq!(remote_ue.metrics.rx_data_pdus, 1);
}

#[test]
fn test_rel18_multi_hop_relay_and_loop_prevention() {
    let dest_ue: u16 = 0x00FF;
    let next_hop: u16 = 0x0033;
    let egress_channel: u8 = 2;

    let mut intermediate_relay = SrapEntity::new(SrapRole::IntermediateRelay, 0x0022);
    intermediate_relay.router.add_route(SrapRouteEntry {
        dest_ue_id: dest_ue,
        next_hop_ue_id: next_hop,
        egress_channel_id: egress_channel,
        hop_distance: 2,
        cost_metric: 10,
    });

    // 1. Packet with valid initial hop count of 4
    let hdr = SrapDataHeader::new_multihop(dest_ue, 1, 4).expect("Valid header");
    let pdu = SrapDataPdu::new_with_header(hdr, b"Multi-hop Payload".to_vec());
    let raw = pdu.encode();

    let (out_ch, out_next_hop, forwarded) = intermediate_relay
        .intermediate_forward_multihop(1, &raw)
        .expect("Forwarding should succeed");

    assert_eq!(out_ch, egress_channel);
    assert_eq!(out_next_hop, next_hop);

    // Verify hop count was decremented from 4 to 3
    let (dec_hdr, _) = SrapDataHeader::decode(&forwarded).expect("Decode forwarded");
    assert_eq!(dec_hdr.hop_count, Some(3));

    // 2. Loop mitigation: Packet arriving with hop_count = 1 (cannot be forwarded further)
    let hdr_expired = SrapDataHeader::new_multihop(dest_ue, 1, 1).expect("Header with 1 hop");
    let pdu_expired = SrapDataPdu::new_with_header(hdr_expired, b"Stale Loop Packet".to_vec());
    let raw_expired = pdu_expired.encode();

    let err = intermediate_relay
        .intermediate_forward_multihop(1, &raw_expired)
        .unwrap_err();

    match err {
        SrapError::HopLimitExceeded { ue_id, hop_count } => {
            assert_eq!(ue_id, dest_ue);
            assert_eq!(hop_count, 1);
        }
        _ => panic!("Expected HopLimitExceeded error"),
    }
    assert_eq!(intermediate_relay.metrics.dropped_hop_limit, 1);

    // 3. Multi-Hop Probe Loop Detection (Route Echo)
    let mut router = SrapMultiHopRouter::new(SRAP_DEFAULT_MAX_HOPS);
    assert!(router.check_and_record_probe(0x100, 1).is_ok());
    assert!(router.check_and_record_probe(0x100, 2).is_ok());

    // Duplicate probe with same sequence number from same originator -> Loop detected!
    let probe_err = router.check_and_record_probe(0x100, 1).unwrap_err();
    match probe_err {
        SrapError::LoopDetected { ue_id, node_id } => {
            assert_eq!(ue_id, 0x100);
            assert_eq!(node_id, 0x100);
        }
        _ => panic!("Expected LoopDetected error"),
    }
}

#[test]
fn test_dynamic_flow_control_backpressure_servo() {
    let mut fc = SrapFlowControlManager::new();
    let ue_id: u16 = 0x55;
    let bearer_id: u8 = 3;

    // Configure limits: high watermark = 5000 bytes, low watermark = 1500 bytes
    fc.configure_limits(ue_id, bearer_id, 5000, 1500);

    // Initial state: not throttled
    assert!(!fc.is_throttled(ue_id, bearer_id));

    // Enqueue 3500 bytes (< 5000) -> No throttle trigger
    let trig1 = fc
        .record_enqueue(ue_id, bearer_id, 3500)
        .expect("Enqueue ok");
    assert!(trig1.is_none());
    assert!(!fc.is_throttled(ue_id, bearer_id));

    // Enqueue 1800 more bytes (total 5300 bytes >= 5000) -> Triggers high watermark throttle
    let trig2 = fc
        .record_enqueue(ue_id, bearer_id, 1800)
        .expect("Enqueue ok");
    assert!(trig2.is_some());
    assert!(fc.is_throttled(ue_id, bearer_id));

    if let Some(SrapControlPdu::FlowControlFeedback {
        ue_id: u,
        bearer_id: b,
        buffer_occupancy_bytes,
        credit_window_kbps,
    }) = trig2
    {
        assert_eq!(u, ue_id);
        assert_eq!(b, bearer_id);
        assert_eq!(buffer_occupancy_bytes, 5300);
        assert_eq!(credit_window_kbps, 0); // Throttled to 0
    } else {
        panic!("Expected FlowControlFeedback");
    }

    // Additional enqueues while already throttled should not re-trigger
    let trig3 = fc
        .record_enqueue(ue_id, bearer_id, 200)
        .expect("Enqueue ok");
    assert!(trig3.is_none());
    assert!(fc.is_throttled(ue_id, bearer_id));

    // Dequeue 3000 bytes -> remaining 2500 bytes (> 1500 low watermark) -> Still throttled
    let resume1 = fc.record_dequeue(ue_id, bearer_id, 3000);
    assert!(resume1.is_none());
    assert!(fc.is_throttled(ue_id, bearer_id));

    // Dequeue 1200 bytes -> remaining 1300 bytes (<= 1500 low watermark) -> Resume signaled!
    let resume2 = fc.record_dequeue(ue_id, bearer_id, 1200);
    assert!(resume2.is_some());
    assert!(!fc.is_throttled(ue_id, bearer_id));

    if let Some(SrapControlPdu::FlowControlFeedback {
        credit_window_kbps, ..
    }) = resume2
    {
        assert_eq!(credit_window_kbps, 1000); // Resumed credit
    } else {
        panic!("Expected resume FlowControlFeedback");
    }
}

#[test]
fn test_error_handling_and_formatting() {
    // 1. Invalid Bearer ID (> 32)
    let err_bearer = SrapDataHeader::new_standard(0x01, 33).unwrap_err();
    assert_eq!(err_bearer, SrapError::InvalidBearerId(33));

    let err_bearer_zero = SrapDataHeader::new_standard(0x01, 0).unwrap_err();
    assert_eq!(err_bearer_zero, SrapError::InvalidBearerId(0));

    // 2. Truncated buffer decoding
    let err_trunc = SrapDataHeader::decode(&[]).unwrap_err();
    assert_eq!(
        err_trunc,
        SrapError::TruncatedBuffer {
            expected: 2,
            actual: 0
        }
    );

    // 3. Display formatting assertions
    let err_map = SrapError::MappingNotFound {
        ue_id: 0x1234,
        bearer_id: 5,
        channel_id: 2,
    };
    let display_str = format!("{}", err_map);
    assert!(display_str.contains("0x1234"));
    assert!(display_str.contains("Bearer 5"));

    let err_hop = SrapError::HopLimitExceeded {
        ue_id: 0x5678,
        hop_count: 0,
    };
    assert!(format!("{}", err_hop).contains("hop limit expired"));

    let err_loop = SrapError::LoopDetected {
        ue_id: 0x1111,
        node_id: 0x2222,
    };
    assert!(format!("{}", err_loop).contains("routing loop detected"));

    let err_overflow = SrapError::BufferOverflow {
        ue_id: 0x01,
        bearer_id: 1,
        capacity: 10000,
    };
    assert!(format!("{}", err_overflow).contains("buffer overflow"));

    // Verify default max bearer constant
    assert_eq!(SRAP_MAX_BEARER_ID, 32);
}

//! Integration tests for 3GPP TS 38.425 F1-U / Xn-U NR User Plane Protocol and Flow Control Engine.

use toy_tcpip::nr_up_38425::{
    DddsCause, DiscardedSnBlock, LostSnRange, NR_U_MAX_SN, NrUpDlDataDeliveryStatus,
    NrUpDlUserData, NrUpError, NrUpFlowController,
};

#[test]
fn test_dl_user_data_wire_round_trip() {
    let payload = vec![0x45, 0x00, 0x00, 0x3c, 0x1a, 0x2b, 0x3c, 0x4d]; // mock IPv4 packet
    let mut pdu = NrUpDlUserData::new(0x123456, payload.clone()).unwrap();
    pdu.report_polling = true;
    pdu.dl_flush = false;
    pdu.discarded_blocks.push(DiscardedSnBlock {
        start_nr_u_sn: 0x120000,
        count: 5,
    });

    let wire = pdu.serialize();
    assert_eq!(wire[0], 0x00); // PDU Type 0
    // Flags: user_data_exist (0x08) | report_polling (0x04) | has_discard (0x01) = 0x0D
    assert_eq!(wire[1], 0x0D);
    assert_eq!(&wire[2..5], &[0x12, 0x34, 0x56]); // 24-bit SN

    let parsed = NrUpDlUserData::parse(&wire).expect("Failed to parse DL USER DATA");
    assert_eq!(parsed.nr_u_sn, 0x123456);
    assert!(parsed.report_polling);
    assert!(!parsed.dl_flush);
    assert!(parsed.user_data_exist);
    assert_eq!(parsed.discarded_blocks.len(), 1);
    assert_eq!(parsed.discarded_blocks[0].start_nr_u_sn, 0x120000);
    assert_eq!(parsed.discarded_blocks[0].count, 5);
    assert_eq!(parsed.payload, payload);
}

#[test]
fn test_dl_data_delivery_status_wire_round_trip() {
    let mut ddds = NrUpDlDataDeliveryStatus::new(131_072); // 128 KB buffer credit
    ddds.highest_delivered_nr_u_sn = Some(0x054321);
    ddds.cause = Some(DddsCause::RadioLinkOutage);
    ddds.final_frame = true;
    ddds.lost_sn_ranges.push(LostSnRange {
        start_sn: 0x054300,
        end_sn: 0x054305,
    });

    let wire = ddds.serialize();
    assert_eq!(wire[0], 0x01); // PDU Type 1

    let parsed = NrUpDlDataDeliveryStatus::parse(&wire).expect("Failed to parse DDDS");
    assert_eq!(parsed.desired_buffer_size, 131_072);
    assert_eq!(parsed.highest_delivered_nr_u_sn, Some(0x054321));
    assert_eq!(parsed.cause, Some(DddsCause::RadioLinkOutage));
    assert!(parsed.final_frame);
    assert_eq!(parsed.lost_sn_ranges.len(), 1);
    assert_eq!(parsed.lost_sn_ranges[0].start_sn, 0x054300);
    assert_eq!(parsed.lost_sn_ranges[0].end_sn, 0x054305);
}

#[test]
fn test_f1u_flow_control_credit_throttling() {
    let mut flow_ctrl = NrUpFlowController::new(2000); // 2000 bytes DU credit
    assert!(flow_ctrl.can_send(800));

    // Send packet 0 (800 bytes)
    let pdu0 = flow_ctrl.send_packet(vec![0xAA; 800], false).unwrap();
    assert_eq!(pdu0.nr_u_sn, 0);
    assert_eq!(flow_ctrl.in_flight_bytes, 800);

    // Send packet 1 (800 bytes) -> in-flight = 1600 bytes
    let pdu1 = flow_ctrl.send_packet(vec![0xBB; 800], false).unwrap();
    assert_eq!(pdu1.nr_u_sn, 1);
    assert_eq!(flow_ctrl.in_flight_bytes, 1600);

    // Attempt packet 2 (800 bytes) -> 1600 + 800 = 2400 > 2000 -> Throttled!
    assert!(!flow_ctrl.can_send(800));
    let err = flow_ctrl.send_packet(vec![0xCC; 800], false).unwrap_err();
    assert!(matches!(
        err,
        NrUpError::BufferOverflow {
            in_flight: 2400,
            credit: 2000
        }
    ));

    // DU delivers packet 0 and sends DDDS acknowledging SN 0
    let mut ddds = NrUpDlDataDeliveryStatus::new(2000);
    ddds.highest_delivered_nr_u_sn = Some(0);
    let retx = flow_ctrl.process_delivery_status(&ddds);
    assert!(retx.is_empty());

    // In-flight bytes reduced by 800 to 800 bytes!
    assert_eq!(flow_ctrl.in_flight_bytes, 800);
    assert_eq!(flow_ctrl.total_delivered_packets, 1);

    // Now packet 2 succeeds!
    let pdu2 = flow_ctrl.send_packet(vec![0xCC; 800], false).unwrap();
    assert_eq!(pdu2.nr_u_sn, 2);
    assert_eq!(flow_ctrl.in_flight_bytes, 1600);
}

#[test]
fn test_f1u_fast_retransmission_on_lost_ranges() {
    let mut flow_ctrl = NrUpFlowController::new(10_000);

    // Send 5 packets (SN 0, 1, 2, 3, 4)
    let _p0 = flow_ctrl.send_packet(vec![0x00; 100], false).unwrap();
    let _p1 = flow_ctrl.send_packet(vec![0x01; 100], false).unwrap();
    let _p2 = flow_ctrl.send_packet(vec![0x02; 100], false).unwrap();
    let _p3 = flow_ctrl.send_packet(vec![0x03; 100], false).unwrap();
    let _p4 = flow_ctrl.send_packet(vec![0x04; 100], false).unwrap();

    assert_eq!(flow_ctrl.in_flight_bytes, 500);

    // DU receives 0, 1, 3, 4, but packet 2 is lost!
    // DU sends DDDS with highest_delivered = 1 and lost_sn_ranges = [2..2]
    let mut ddds = NrUpDlDataDeliveryStatus::new(10_000);
    ddds.highest_delivered_nr_u_sn = Some(1);
    ddds.lost_sn_ranges.push(LostSnRange {
        start_sn: 2,
        end_sn: 2,
    });

    let retransmitted = flow_ctrl.process_delivery_status(&ddds);

    // Verify fast retransmission triggered for packet 2
    assert_eq!(retransmitted.len(), 1);
    assert_eq!(retransmitted[0].nr_u_sn, 2);
    assert_eq!(retransmitted[0].payload, vec![0x02; 100]);
    assert!(retransmitted[0].report_polling); // Poll flag set on retransmit

    assert_eq!(flow_ctrl.total_retransmitted_packets, 1);
    assert_eq!(flow_ctrl.total_delivered_packets, 2); // SN 0 and 1 acknowledged
}

#[test]
fn test_24bit_circular_sequence_number_wrapping() {
    let mut flow_ctrl = NrUpFlowController::new(10_000);
    flow_ctrl.next_nr_u_sn = NR_U_MAX_SN; // 0xFFFFFF

    let p_last = flow_ctrl.send_packet(vec![0x11; 50], false).unwrap();
    assert_eq!(p_last.nr_u_sn, NR_U_MAX_SN);

    // Wraps around to 0
    let p_wrap = flow_ctrl.send_packet(vec![0x22; 50], false).unwrap();
    assert_eq!(p_wrap.nr_u_sn, 0);

    // Next is 1
    let p_next = flow_ctrl.send_packet(vec![0x33; 50], false).unwrap();
    assert_eq!(p_next.nr_u_sn, 1);

    // DDDS delivers up to SN 0 across the boundary
    let mut ddds = NrUpDlDataDeliveryStatus::new(10_000);
    ddds.highest_delivered_nr_u_sn = Some(0);
    let retx = flow_ctrl.process_delivery_status(&ddds);
    assert!(retx.is_empty());

    // Both NR_U_MAX_SN and 0 acknowledged!
    assert_eq!(flow_ctrl.total_delivered_packets, 2);
    assert_eq!(flow_ctrl.in_flight_bytes, 50); // Only SN 1 remains unacked
}

//! Integration tests for 3GPP TS 38.322 5G NR RLC Engine.

use toy_tcpip::rlc_5g::{
    RlcAmDataPdu, RlcAmSnSize, RlcEntity, RlcEntityMode, RlcNackRange, RlcSegmentationInfo,
    RlcStatusPdu,
};

#[test]
fn test_rlc_am_pdu_framing_and_status_pdu_round_trip() {
    // 1. 12-bit AM Data PDU (Unsegmented Full SDU)
    let pdu_12 = RlcAmDataPdu {
        sn_size: RlcAmSnSize::Am12Bits,
        poll: true,
        si: RlcSegmentationInfo::Full,
        sn: 100,
        so: None,
        payload: b"RLC-AM-12bit-Payload".to_vec(),
    };
    let wire_12 = pdu_12.serialize();
    assert_eq!(wire_12.len(), 3 + pdu_12.payload.len());
    let parsed_12 = RlcAmDataPdu::parse(RlcAmSnSize::Am12Bits, &wire_12).unwrap();
    assert_eq!(parsed_12, pdu_12);

    // 2. 18-bit AM Data PDU (Segmented Middle Segment)
    let pdu_18 = RlcAmDataPdu {
        sn_size: RlcAmSnSize::Am18Bits,
        poll: false,
        si: RlcSegmentationInfo::MiddleSegment,
        sn: 50_000,
        so: Some(1024),
        payload: b"RLC-AM-18bit-Segment".to_vec(),
    };
    let wire_18 = pdu_18.serialize();
    assert_eq!(wire_18.len(), 3 + 2 + pdu_18.payload.len()); // Header 3 + SO 2 + payload
    let parsed_18 = RlcAmDataPdu::parse(RlcAmSnSize::Am18Bits, &wire_18).unwrap();
    assert_eq!(parsed_18, pdu_18);

    // 3. Status PDU with NACK list
    let status_pdu = RlcStatusPdu {
        ack_sn: 105,
        nacks: vec![
            RlcNackRange {
                nack_sn: 101,
                so_start: None,
                so_end: None,
            },
            RlcNackRange {
                nack_sn: 103,
                so_start: None,
                so_end: None,
            },
        ],
    };
    let wire_status = status_pdu.serialize();
    assert_eq!(wire_status.len(), 3 + 3 + 3); // 3 bytes header + 2x3 bytes NACKs
    let parsed_status = RlcStatusPdu::parse(&wire_status).unwrap();
    assert_eq!(parsed_status, status_pdu);
}

#[test]
fn test_rlc_segmentation_and_reassembly() {
    let mut tx = RlcEntity::new(RlcEntityMode::Am {
        sn_size: RlcAmSnSize::Am18Bits,
    });
    let mut rx = RlcEntity::new(RlcEntityMode::Am {
        sn_size: RlcAmSnSize::Am18Bits,
    });

    // Generate 1500-byte SDU
    let original_sdu: Vec<u8> = (0..1500).map(|i| (i % 256) as u8).collect();

    // Segment with grant_size = 600 bytes
    let segments = tx.segment_and_send(&original_sdu, 600, true);
    assert_eq!(segments.len(), 3);

    // Verify segmentation info
    assert_eq!(segments[0].si, RlcSegmentationInfo::FirstSegment);
    assert_eq!(segments[0].payload.len(), 600);
    assert_eq!(segments[0].so, None);
    assert!(!segments[0].poll);

    assert_eq!(segments[1].si, RlcSegmentationInfo::MiddleSegment);
    assert_eq!(segments[1].payload.len(), 600);
    assert_eq!(segments[1].so, Some(600));
    assert!(!segments[1].poll);

    assert_eq!(segments[2].si, RlcSegmentationInfo::LastSegment);
    assert_eq!(segments[2].payload.len(), 300);
    assert_eq!(segments[2].so, Some(1200));
    assert!(segments[2].poll); // Poll on last segment

    // Deliver to receiver in scrambled order: segment 0, segment 2, then segment 1
    assert_eq!(rx.receive_am_pdu(&segments[0]).unwrap(), None); // Incomplete
    assert_eq!(rx.receive_am_pdu(&segments[2]).unwrap(), None); // Incomplete
    let reassembled = rx.receive_am_pdu(&segments[1]).unwrap(); // Complete!

    assert!(reassembled.is_some());
    assert_eq!(reassembled.unwrap(), original_sdu);
    assert_eq!(rx.delivered_sdus.len(), 1);
    assert_eq!(rx.delivered_sdus[0], original_sdu);
}

#[test]
fn test_rlc_am_arq_nack_and_retransmission() {
    let mut tx = RlcEntity::new(RlcEntityMode::Am {
        sn_size: RlcAmSnSize::Am18Bits,
    });
    let mut rx = RlcEntity::new(RlcEntityMode::Am {
        sn_size: RlcAmSnSize::Am18Bits,
    });

    let sdu0 = b"Packet-0-Data".to_vec();
    let sdu1 = b"Packet-1-Data".to_vec();
    let sdu2 = b"Packet-2-Data".to_vec();

    let pdu0 = &tx.segment_and_send(&sdu0, 1000, false)[0];
    let _pdu1 = &tx.segment_and_send(&sdu1, 1000, false)[0];
    let pdu2 = &tx.segment_and_send(&sdu2, 1000, true)[0];

    // Simulate packet 1 loss in air interface: deliver 0 and 2
    rx.receive_am_pdu(pdu0).unwrap();
    rx.receive_am_pdu(pdu2).unwrap();

    assert_eq!(rx.delivered_sdus.len(), 2); // Full SDUs delivered directly

    // Simulate missing SDU 1 tracking: insert empty reassembly state for gap detection
    let mut status = RlcStatusPdu {
        ack_sn: 3,
        nacks: vec![RlcNackRange {
            nack_sn: 1,
            so_start: None,
            so_end: None,
        }],
    };

    // Transmitter processes Status PDU
    tx.process_status_pdu(&status);

    // Verify SDU 0 is freed from tx_buffer, and SDU 1 is enqueued for retransmission
    assert!(!tx.tx_buffer.contains_key(&0));
    assert_eq!(tx.retransmit_queue.len(), 1);
    assert_eq!(tx.retransmit_queue[0].sn, 1);

    // Retransmit packet 1
    let retransmitted_pdu = tx.retransmit_queue.remove(0);
    rx.receive_am_pdu(&retransmitted_pdu).unwrap();

    assert_eq!(rx.delivered_sdus.len(), 3);
    assert_eq!(rx.delivered_sdus[2], sdu1);

    // Receiver now sends clean Status PDU (all ACKed)
    status.nacks.clear();
    tx.process_status_pdu(&status);
    assert!(tx.tx_buffer.is_empty());
}

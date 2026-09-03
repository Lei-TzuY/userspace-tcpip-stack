//! Integration tests for 3GPP TS 38.323 5G NR PDCP Engine.

use toy_tcpip::pdcp_5g::{PdcpBearerType, PdcpControlPdu, PdcpDataPdu, PdcpEntity, PdcpSnSize};

#[test]
fn test_pdcp_12bit_and_18bit_framing_round_trip() {
    // 1. 12-bit Data PDU (e.g. SRB1)
    let pdu_12 = PdcpDataPdu {
        sn_size: PdcpSnSize::Sn12Bits,
        sn: 3000, // 0x0BB8
        payload: b"5G-RRC-SRB1-Transfer".to_vec(),
    };
    let wire_12 = pdu_12.serialize();
    assert_eq!(wire_12.len(), 2 + pdu_12.payload.len());
    // Octet 1: D/C=1 (0x80) | SN[11..8]=0x0B -> 0x8B
    assert_eq!(wire_12[0], 0x8B);
    // Octet 2: SN[7..0] = 0xB8
    assert_eq!(wire_12[1], 0xB8);

    let parsed_12 = PdcpDataPdu::parse(PdcpSnSize::Sn12Bits, &wire_12).unwrap();
    assert_eq!(parsed_12.sn, 3000);
    assert_eq!(parsed_12.payload, b"5G-RRC-SRB1-Transfer");

    // 2. 18-bit Data PDU (e.g. eMBB DRB)
    let pdu_18 = PdcpDataPdu {
        sn_size: PdcpSnSize::Sn18Bits,
        sn: 200_000, // 0x030D40
        payload: b"5G-eMBB-High-Speed-Data".to_vec(),
    };
    let wire_18 = pdu_18.serialize();
    assert_eq!(wire_18.len(), 3 + pdu_18.payload.len());
    // Octet 1: D/C=1 (0x80) | SN[17..16]=0x03 -> 0x83
    assert_eq!(wire_18[0], 0x83);
    // Octet 2: SN[15..8] = 0x0D
    assert_eq!(wire_18[1], 0x0D);
    // Octet 3: SN[7..0] = 0x40
    assert_eq!(wire_18[2], 0x40);

    let parsed_18 = PdcpDataPdu::parse(PdcpSnSize::Sn18Bits, &wire_18).unwrap();
    assert_eq!(parsed_18.sn, 200_000);
    assert_eq!(parsed_18.payload, b"5G-eMBB-High-Speed-Data");
}

#[test]
fn test_pdcp_hfn_rollover_and_count_derivation() {
    // 12-bit SN: max SN = 4095
    let mut entity = PdcpEntity::new(PdcpBearerType::Drb, PdcpSnSize::Sn12Bits);
    entity.rx_next = 4095; // at the edge of rollover

    // Receive SN 0 (should rollover HFN from 0 to 1 -> COUNT = 4096)
    let count_0 = entity.derive_rx_count(0);
    assert_eq!(count_0, 4096);

    // Receive SN 1 -> COUNT = 4097
    let count_1 = entity.derive_rx_count(1);
    assert_eq!(count_1, 4097);

    // 18-bit SN: max SN = 262143
    let mut entity_18 = PdcpEntity::new(PdcpBearerType::Drb, PdcpSnSize::Sn18Bits);
    entity_18.rx_next = 262143;

    let count_18_0 = entity_18.derive_rx_count(0);
    assert_eq!(count_18_0, 262144);
}

#[test]
fn test_pdcp_out_of_order_reordering_and_deduplication() {
    let mut tx = PdcpEntity::new(PdcpBearerType::Drb, PdcpSnSize::Sn18Bits);
    let mut rx = PdcpEntity::new(PdcpBearerType::Drb, PdcpSnSize::Sn18Bits);

    let p0 = tx.transmit_sdu(b"Pkt-0".to_vec());
    let p1 = tx.transmit_sdu(b"Pkt-1".to_vec());
    let p2 = tx.transmit_sdu(b"Pkt-2".to_vec());
    let p3 = tx.transmit_sdu(b"Pkt-3".to_vec());

    // Deliver scrambled order: 0, 2, 1, 3, and a duplicate of 2
    rx.receive_pdu(&p0).unwrap();
    assert_eq!(rx.delivered_sdus.len(), 1);

    rx.receive_pdu(&p2).unwrap();
    assert_eq!(rx.delivered_sdus.len(), 1); // Gap at 1, p2 is buffered in reordering_buffer
    assert_eq!(rx.reordering_buffer.len(), 1);

    // Receive missing packet 1 -> triggers flush of 1 and 2
    rx.receive_pdu(&p1).unwrap();
    assert_eq!(rx.delivered_sdus.len(), 3);
    assert!(rx.reordering_buffer.is_empty());

    // Receive duplicate packet 2 -> discarded
    rx.receive_pdu(&p2).unwrap();
    assert_eq!(rx.duplicate_pdus, 1);
    assert_eq!(rx.delivered_sdus.len(), 3);

    // Receive packet 3
    rx.receive_pdu(&p3).unwrap();
    assert_eq!(rx.delivered_sdus.len(), 4);

    // Verify strict in-order delivery
    assert_eq!(rx.delivered_sdus[0], b"Pkt-0");
    assert_eq!(rx.delivered_sdus[1], b"Pkt-1");
    assert_eq!(rx.delivered_sdus[2], b"Pkt-2");
    assert_eq!(rx.delivered_sdus[3], b"Pkt-3");
}

#[test]
fn test_pdcp_status_report_generation_and_gap_detection() {
    let mut rx = PdcpEntity::new(PdcpBearerType::Drb, PdcpSnSize::Sn18Bits);

    // Receive packet 0
    let p0 = PdcpDataPdu {
        sn_size: PdcpSnSize::Sn18Bits,
        sn: 0,
        payload: b"0".to_vec(),
    };
    rx.receive_pdu(&p0).unwrap();

    // Packet 1 missing, receive packet 2
    let p2 = PdcpDataPdu {
        sn_size: PdcpSnSize::Sn18Bits,
        sn: 2,
        payload: b"2".to_vec(),
    };
    rx.receive_pdu(&p2).unwrap();

    // Generate Status Report
    let report = rx.generate_status_report().unwrap();
    let wire = match &report {
        PdcpControlPdu::StatusReport { fmc, bitmap } => {
            assert_eq!(*fmc, 1); // FMC = 1
            assert_eq!(bitmap.len(), 1);
            // Bitmap for COUNT = FMC + 1 = 2: bit 7 should be 1
            assert_eq!(bitmap[0] & 0x80, 0x80);
            report.serialize()
        }
    };

    let parsed = PdcpControlPdu::parse(&wire).unwrap();
    assert_eq!(parsed, report);
}

#[test]
fn test_pdcp_t_reordering_timer_expiry() {
    let mut rx = PdcpEntity::new(PdcpBearerType::Drb, PdcpSnSize::Sn18Bits);

    let p0 = PdcpDataPdu {
        sn_size: PdcpSnSize::Sn18Bits,
        sn: 0,
        payload: b"0".to_vec(),
    };
    let p2 = PdcpDataPdu {
        sn_size: PdcpSnSize::Sn18Bits,
        sn: 2,
        payload: b"2".to_vec(),
    };

    rx.receive_pdu(&p0).unwrap();
    rx.receive_pdu(&p2).unwrap();

    assert_eq!(rx.rx_deliv, 1);
    assert_eq!(rx.rx_reord, 3);
    assert_eq!(rx.delivered_sdus.len(), 1);

    // Timer expires
    rx.handle_t_reordering_expiry();

    // Packet 2 delivered even though packet 1 was permanently lost
    assert_eq!(rx.delivered_sdus.len(), 2);
    assert_eq!(rx.delivered_sdus[1], b"2");
    assert_eq!(rx.rx_deliv, 3);
}

//! Integration tests for `mac_5g` — 3GPP TS 38.321 5G NR MAC Engine.

use toy_tcpip::mac_5g::*;

// ---------------------------------------------------------------------------
// 1. MAC PDU serialization/deserialization roundtrip with multiple SDUs
// ---------------------------------------------------------------------------

#[test]
fn test_mac_pdu_multi_sdu_roundtrip() {
    let mut pdu = MacPdu::new();

    // SDU on LCID 1 (SRB1)
    pdu.add_element(MacPduElement::Sdu {
        lcid: 1,
        payload: vec![0x11, 0x22, 0x33],
    });
    // SDU on LCID 4 (DRB)
    pdu.add_element(MacPduElement::Sdu {
        lcid: 4,
        payload: vec![0xAA, 0xBB, 0xCC, 0xDD],
    });
    // Padding
    pdu.add_element(MacPduElement::Padding { length: 5 });

    let wire = pdu.to_bytes();
    // SubPDU 1: subhdr(2) + payload(3) = 5
    // SubPDU 2: subhdr(2) + payload(4) = 6
    // Padding: subhdr(1) + zeros(5) = 6
    // Total = 17
    assert_eq!(wire.len(), 17);

    let parsed = MacPdu::from_bytes(&wire).unwrap();
    assert_eq!(parsed.elements.len(), 3);

    // Verify first SDU
    match &parsed.elements[0] {
        MacPduElement::Sdu { lcid, payload } => {
            assert_eq!(*lcid, 1);
            assert_eq!(payload, &[0x11, 0x22, 0x33]);
        }
        _ => panic!("Expected SDU on LCID 1"),
    }

    // Verify second SDU
    match &parsed.elements[1] {
        MacPduElement::Sdu { lcid, payload } => {
            assert_eq!(*lcid, 4);
            assert_eq!(payload, &[0xAA, 0xBB, 0xCC, 0xDD]);
        }
        _ => panic!("Expected SDU on LCID 4"),
    }

    // Verify padding
    match &parsed.elements[2] {
        MacPduElement::Padding { length } => {
            assert_eq!(*length, 5);
        }
        _ => panic!("Expected Padding"),
    }
}

// ---------------------------------------------------------------------------
// 2. MAC Control Elements: Short BSR, C-RNTI, Timing Advance
// ---------------------------------------------------------------------------

#[test]
fn test_mac_ce_short_bsr_encode_decode() {
    let bsr = MacPduElement::ShortBsr {
        lcg_id: 2,
        buffer_size_index: 31,
    };

    let payload = bsr.payload_bytes();
    assert_eq!(payload.len(), 1);
    // LCG ID=2 → bits 7-6 = 0b10, BS=31 → bits 5-0 = 0b011111
    assert_eq!(payload[0], (2 << 6) | 31);

    // Roundtrip through MAC PDU
    let mut pdu = MacPdu::new();
    pdu.add_element(bsr);
    let wire = pdu.to_bytes();
    let parsed = MacPdu::from_bytes(&wire).unwrap();

    match &parsed.elements[0] {
        MacPduElement::ShortBsr {
            lcg_id,
            buffer_size_index,
        } => {
            assert_eq!(*lcg_id, 2);
            assert_eq!(*buffer_size_index, 31);
        }
        _ => panic!("Expected Short BSR"),
    }
}

#[test]
fn test_mac_ce_crnti_encode_decode() {
    let crnti = MacPduElement::CRnti { c_rnti: 0xABCD };

    let payload = crnti.payload_bytes();
    assert_eq!(payload.len(), 2);
    assert_eq!(payload[0], 0xAB);
    assert_eq!(payload[1], 0xCD);

    let mut pdu = MacPdu::new();
    pdu.add_element(crnti);
    let wire = pdu.to_bytes();
    let parsed = MacPdu::from_bytes(&wire).unwrap();

    match &parsed.elements[0] {
        MacPduElement::CRnti { c_rnti } => {
            assert_eq!(*c_rnti, 0xABCD);
        }
        _ => panic!("Expected C-RNTI CE"),
    }
}

#[test]
fn test_mac_ce_timing_advance_command() {
    let ta = MacPduElement::TimingAdvanceCommand {
        tag_id: 1,
        ta_command: 42,
    };

    let payload = ta.payload_bytes();
    assert_eq!(payload.len(), 1);
    assert_eq!(payload[0], (1 << 6) | 42);

    let mut pdu = MacPdu::new();
    pdu.add_element(ta);
    let wire = pdu.to_bytes();

    // Roundtrip: parse as DL MAC PDU
    let mut mac = MacEntity::new(8, 4);
    let _parsed = mac.receive_dl_pdu(&wire).unwrap();

    // The TA CE should appear in received_ces
    assert_eq!(mac.received_ces.len(), 1);
    match &mac.received_ces[0] {
        MacPduElement::TimingAdvanceCommand { tag_id, ta_command } => {
            assert_eq!(*tag_id, 1);
            assert_eq!(*ta_command, 42);
        }
        _ => panic!("Expected Timing Advance CE"),
    }
}

// ---------------------------------------------------------------------------
// 3. HARQ process lifecycle: new TX → ACK and new TX → NACK → retransmission
// ---------------------------------------------------------------------------

#[test]
fn test_harq_process_ack_lifecycle() {
    let mut harq = HarqProcess::new(0, 4);
    assert_eq!(harq.state, HarqState::Idle);
    assert!(!harq.ndi);

    // New transmission
    harq.new_transmission(vec![0x01, 0x02, 0x03]);
    assert_eq!(harq.state, HarqState::WaitingForFeedback);
    assert!(harq.ndi); // NDI toggled
    assert_eq!(harq.tx_count, 1);
    assert_eq!(harq.redundancy_version, 0);
    assert!(harq.tb_data.is_some());

    // Receive ACK
    harq.receive_ack();
    assert_eq!(harq.state, HarqState::Idle);
    assert!(harq.tb_data.is_none());
}

#[test]
fn test_harq_process_nack_retransmission_rv_cycling() {
    let mut harq = HarqProcess::new(3, 4);

    harq.new_transmission(vec![0xAA, 0xBB]);
    assert_eq!(harq.redundancy_version, 0);

    // NACK → should schedule retransmission
    let can_retx = harq.receive_nack();
    assert!(can_retx);
    assert_eq!(harq.state, HarqState::PendingRetransmission);

    // Retransmit → RV 0 → 2
    let tb = harq.retransmit().unwrap();
    assert_eq!(tb, vec![0xAA, 0xBB]);
    assert_eq!(harq.redundancy_version, 2);
    assert_eq!(harq.tx_count, 2);

    // NACK again → retransmit → RV 2 → 3
    harq.receive_nack();
    harq.retransmit();
    assert_eq!(harq.redundancy_version, 3);
    assert_eq!(harq.tx_count, 3);

    // NACK again → retransmit → RV 3 → 1
    harq.receive_nack();
    harq.retransmit();
    assert_eq!(harq.redundancy_version, 1);
    assert_eq!(harq.tx_count, 4);

    // NACK with max_retx=4 → tx_count=4 >= max_retx → failure, reset
    let can_retx = harq.receive_nack();
    assert!(!can_retx);
    assert_eq!(harq.state, HarqState::Idle);
    assert!(harq.tb_data.is_none());
}

// ---------------------------------------------------------------------------
// 4. Logical Channel Prioritization + UL PDU assembly
// ---------------------------------------------------------------------------

#[test]
fn test_mac_lcp_ul_pdu_assembly() {
    let mut mac = MacEntity::new(8, 4);

    // Configure two logical channels with different priorities
    mac.configure_logical_channel(LogicalChannelConfig {
        lcid: 1,
        priority: 1, // Highest priority (SRB1)
        pbr_bytes_per_tti: 100,
        bucket_size_duration: 10,
    });
    mac.configure_logical_channel(LogicalChannelConfig {
        lcid: 4,
        priority: 4, // Lower priority (DRB)
        pbr_bytes_per_tti: 200,
        bucket_size_duration: 10,
    });

    // Enqueue data on both channels
    mac.enqueue_data(1, 50); // SRB1: 50 bytes
    mac.enqueue_data(4, 150); // DRB: 150 bytes

    // Assemble UL PDU with 300-byte grant
    let (harq_id, pdu) = mac.assemble_ul_pdu(300).unwrap();
    assert_eq!(harq_id, 0); // First HARQ process

    // Should have served both channels + padding
    let mut found_lcid1 = false;
    let mut found_lcid4 = false;
    let mut has_padding = false;

    for elem in &pdu.elements {
        match elem {
            MacPduElement::Sdu { lcid: 1, payload } => {
                found_lcid1 = true;
                assert_eq!(payload.len(), 50);
            }
            MacPduElement::Sdu { lcid: 4, payload } => {
                found_lcid4 = true;
                assert_eq!(payload.len(), 150);
            }
            MacPduElement::Padding { .. } => {
                has_padding = true;
            }
            _ => {}
        }
    }

    assert!(found_lcid1, "SRB1 data should be included");
    assert!(found_lcid4, "DRB data should be included");
    assert!(has_padding, "Should have padding");

    // Verify HARQ process is now WaitingForFeedback
    assert_eq!(mac.harq_processes[0].state, HarqState::WaitingForFeedback);
}

// ---------------------------------------------------------------------------
// 5. DL PDU demultiplexing with mixed SDUs and CEs
// ---------------------------------------------------------------------------

#[test]
fn test_mac_dl_demux_mixed_sdus_and_ces() {
    let mut dl_pdu = MacPdu::new();

    // DL SDU on LCID 1 (DCCH/SRB1)
    dl_pdu.add_element(MacPduElement::Sdu {
        lcid: 1,
        payload: vec![0x01, 0x02, 0x03, 0x04, 0x05],
    });

    // Timing Advance MAC CE
    dl_pdu.add_element(MacPduElement::TimingAdvanceCommand {
        tag_id: 0,
        ta_command: 15,
    });

    // DL SDU on LCID 5 (DTCH/DRB)
    dl_pdu.add_element(MacPduElement::Sdu {
        lcid: 5,
        payload: vec![0xFF; 20],
    });

    // Padding
    dl_pdu.add_element(MacPduElement::Padding { length: 10 });

    let wire = dl_pdu.to_bytes();

    // Receive and demultiplex
    let mut mac = MacEntity::new(8, 4);
    let _parsed = mac.receive_dl_pdu(&wire).unwrap();

    // Should have 2 SDUs delivered
    assert_eq!(mac.received_sdus.len(), 2);
    assert_eq!(mac.received_sdus[0].0, 1);
    assert_eq!(mac.received_sdus[0].1.len(), 5);
    assert_eq!(mac.received_sdus[1].0, 5);
    assert_eq!(mac.received_sdus[1].1.len(), 20);

    // Should have 1 CE (Timing Advance)
    assert_eq!(mac.received_ces.len(), 1);
}

// ---------------------------------------------------------------------------
// 6. 16-bit length field for large SDUs (> 255 bytes)
// ---------------------------------------------------------------------------

#[test]
fn test_mac_pdu_large_sdu_16bit_length() {
    let large_payload = vec![0xCC; 500];

    let mut pdu = MacPdu::new();
    pdu.add_element(MacPduElement::Sdu {
        lcid: 3,
        payload: large_payload.clone(),
    });

    let wire = pdu.to_bytes();
    // Subheader: 3 bytes (R=0, F=1, LCID=3, L=500 in 16-bit)
    // Payload: 500 bytes
    assert_eq!(wire.len(), 3 + 500);
    assert_eq!(wire[0], 0x40 | 3); // F=1 flag set

    let parsed = MacPdu::from_bytes(&wire).unwrap();
    match &parsed.elements[0] {
        MacPduElement::Sdu { lcid, payload } => {
            assert_eq!(*lcid, 3);
            assert_eq!(payload.len(), 500);
            assert_eq!(payload[0], 0xCC);
        }
        _ => panic!("Expected SDU"),
    }
}

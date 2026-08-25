use toy_tcpip::synce_esmc::{
    QualityLevel, SyncEEsmcEngine, SyncEEsmcPacket, ESMC_SUBTYPE, ITU_T_ESMC_SUBTYPE, ITU_T_OUI,
};

#[test]
fn test_synce_esmc_pdu_serialization_and_parsing() {
    let pkt = SyncEEsmcPacket::new(true, QualityLevel::QlPrc);
    let wire = pkt.serialize();

    assert!(wire.len() >= 36);
    assert_eq!(wire[0], ESMC_SUBTYPE);
    assert_eq!(&wire[1..4], &ITU_T_OUI);
    assert_eq!(u16::from_be_bytes([wire[4], wire[5]]), ITU_T_ESMC_SUBTYPE);
    assert_eq!(wire[6] & 0x08, 0x08); // Event flag set

    let parsed = SyncEEsmcPacket::parse(&wire).expect("parse ESMC PDU");
    assert_eq!(parsed.event_flag, true);
    assert_eq!(parsed.quality_level, QualityLevel::QlPrc);
}

#[test]
fn test_synce_clock_selection_arbitration_and_failover() {
    let mut engine = SyncEEsmcEngine::new();

    engine.set_port_priority(1, 10);
    engine.set_port_priority(2, 20);
    engine.set_port_priority(3, 5);

    // Port 1 receives QL-SSU-A (Rank 2)
    engine.process_rx_esmc(1, &SyncEEsmcPacket::new(false, QualityLevel::QlSsuA));
    assert_eq!(engine.selected_port, Some(1));
    assert_eq!(engine.selected_ql, QualityLevel::QlSsuA);

    // Port 2 receives QL-PRC (Rank 1 - Superior Quality)
    engine.process_rx_esmc(2, &SyncEEsmcPacket::new(false, QualityLevel::QlPrc));
    assert_eq!(engine.selected_port, Some(2));
    assert_eq!(engine.selected_ql, QualityLevel::QlPrc);

    // Port 3 receives QL-PRC (Rank 1, but Priority 5 is higher than Port 2's Priority 20)
    engine.process_rx_esmc(3, &SyncEEsmcPacket::new(false, QualityLevel::QlPrc));
    assert_eq!(engine.selected_port, Some(3));
    assert_eq!(engine.selected_ql, QualityLevel::QlPrc);

    // Port 3 fails and sends QL-DNU (Do Not Use)
    engine.process_rx_esmc(3, &SyncEEsmcPacket::new(true, QualityLevel::QlDnu));
    // Failover back to Port 2 (next best QL-PRC)
    assert_eq!(engine.selected_port, Some(2));
    assert_eq!(engine.selected_ql, QualityLevel::QlPrc);
}

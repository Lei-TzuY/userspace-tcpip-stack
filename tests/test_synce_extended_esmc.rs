use toy_tcpip::synce_esmc::{
    EXTENDED_QL_TLV_LEN, EnhancedQualityLevel, ExtendedQlTlv, QualityLevel, QualityLevelOption2,
    SyncEEsmcEngine, SyncEEsmcPacket, TLV_TYPE_EXTENDED_QL,
};

#[test]
fn test_synce_extended_ql_tlv_serialization_and_parsing() {
    let clock_id = [0x00, 0x11, 0x22, 0xFF, 0xFE, 0x33, 0x44, 0x55];
    let mut ext_tlv = ExtendedQlTlv::new(EnhancedQualityLevel::QlEeec, clock_id);
    ext_tlv.mixed_network = true;
    ext_tlv.cascaded_eeec_count = 3;
    ext_tlv.cascaded_eprtc_count = 1;

    let wire_tlv = ext_tlv.serialize();
    assert_eq!(wire_tlv[0], TLV_TYPE_EXTENDED_QL);
    assert_eq!(
        u16::from_be_bytes([wire_tlv[1], wire_tlv[2]]),
        EXTENDED_QL_TLV_LEN
    );
    assert_eq!(wire_tlv[3], EnhancedQualityLevel::QlEeec as u8);
    assert_eq!(&wire_tlv[4..12], &clock_id);
    assert_eq!(wire_tlv[12] & 0x01, 1);
    assert_eq!(wire_tlv[13], 3);
    assert_eq!(wire_tlv[14], 1);

    let parsed = ExtendedQlTlv::parse(&wire_tlv).expect("parse extended QL TLV");
    assert_eq!(parsed.enhanced_ql, EnhancedQualityLevel::QlEeec);
    assert_eq!(parsed.clock_identity, clock_id);
    assert!(parsed.mixed_network);
    assert_eq!(parsed.cascaded_eeec_count, 3);
    assert_eq!(parsed.cascaded_eprtc_count, 1);
}

#[test]
fn test_synce_esmc_packet_with_extended_ql() {
    let clock_id = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11];
    let ext_tlv = ExtendedQlTlv::new(EnhancedQualityLevel::QlEprtc, clock_id);

    let pkt = SyncEEsmcPacket::new(true, QualityLevel::QlPrc).with_extended_ql(ext_tlv);
    let wire = pkt.serialize();

    let parsed = SyncEEsmcPacket::parse(&wire).expect("parse ESMC PDU with Extended QL");
    assert!(parsed.event_flag);
    assert_eq!(parsed.quality_level, QualityLevel::QlPrc);
    assert!(parsed.extended_ql.is_some());

    let ext = parsed.extended_ql.unwrap();
    assert_eq!(ext.enhanced_ql, EnhancedQualityLevel::QlEprtc);
    assert_eq!(ext.clock_identity, clock_id);
}

#[test]
fn test_synce_extended_ql_arbitration_hierarchy() {
    let mut engine = SyncEEsmcEngine::new();

    // Port 1: Legacy QL-PRC (Option I)
    let pkt1 = SyncEEsmcPacket::new(false, QualityLevel::QlPrc);
    engine.process_rx_esmc(1, &pkt1);
    assert_eq!(engine.selected_port, Some(1));

    // Port 2: QL-PRC with Extended QL-ePRTC (Superior to legacy PRC)
    let clk2 = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let ext2 = ExtendedQlTlv::new(EnhancedQualityLevel::QlEprtc, clk2);
    let pkt2 = SyncEEsmcPacket::new(false, QualityLevel::QlPrc).with_extended_ql(ext2);
    engine.process_rx_esmc(2, &pkt2);

    assert_eq!(engine.selected_port, Some(2));
    assert_eq!(engine.selected_ext_ql, Some(EnhancedQualityLevel::QlEprtc));
}

#[test]
fn test_synce_wtr_and_holdover_arbitration() {
    let mut engine = SyncEEsmcEngine::new();
    // 3 ticks WTR duration
    engine.set_wtr_duration(3);

    // Port 1 receives valid QL-PRC
    let pkt_ok = SyncEEsmcPacket::new(false, QualityLevel::QlPrc);
    engine.process_rx_esmc(1, &pkt_ok);
    assert_eq!(engine.selected_port, Some(1));
    assert!(!engine.holdover_active);

    // Port 1 fails with QL-DNU -> enters Holdover mode
    let pkt_dnu = SyncEEsmcPacket::new(true, QualityLevel::QlDnu);
    engine.process_rx_esmc(1, &pkt_dnu);
    assert_eq!(engine.selected_port, None);
    assert!(engine.holdover_active);

    // Port 1 recovers with QL-PRC -> enters WaitToRestore state, should NOT immediately become active
    engine.process_rx_esmc(1, &pkt_ok);
    assert_eq!(engine.selected_port, None); // Still in WTR!

    // Tick WTR 1
    engine.tick_wtr();
    assert_eq!(engine.selected_port, None);

    // Tick WTR 2
    engine.tick_wtr();
    assert_eq!(engine.selected_port, None);

    // Tick WTR 3 (Timer expired -> port becomes Active and is selected)
    engine.tick_wtr();
    assert_eq!(engine.selected_port, Some(1));
    assert_eq!(engine.selected_ql, QualityLevel::QlPrc);
    assert!(!engine.holdover_active);
}

#[test]
fn test_synce_option_2_ssm_ranking() {
    assert_eq!(QualityLevelOption2::QlPrs.rank(), 1);
    assert_eq!(QualityLevelOption2::QlStu.rank(), 2);
    assert_eq!(QualityLevelOption2::QlSt2.rank(), 3);
    assert_eq!(QualityLevelOption2::QlTnc.rank(), 4);
    assert_eq!(QualityLevelOption2::QlSt3e.rank(), 5);
    assert_eq!(QualityLevelOption2::QlSt3.rank(), 6);
    assert_eq!(QualityLevelOption2::QlSmc.rank(), 7);
    assert_eq!(QualityLevelOption2::QlProv.rank(), 8);
    assert_eq!(QualityLevelOption2::QlDus.rank(), 254);
}

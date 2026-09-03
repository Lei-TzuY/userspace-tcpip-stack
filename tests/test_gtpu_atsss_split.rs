use toy_tcpip::gtpu_atsss_split::{AtsssAccessLeg, AtsssSteeringRule, GtpuAtsssSplitEngine};

#[test]
fn test_gtpu_atsss_split_and_failover() {
    let session_id = 0x99001122;

    // 1. Configure Weighted Split (2 : 1 ratio: 66.7% Cellular, 33.3% Wi-Fi)
    let mut engine = GtpuAtsssSplitEngine::new(
        session_id,
        AtsssSteeringRule::WeightedSplit {
            weight_3gpp: 2,
            weight_wifi: 1,
        },
    );

    let pkt1 = engine.split_packet(500).expect("packet split");
    assert_eq!(pkt1.leg, AtsssAccessLeg::ThreeGppCellular);
    assert_eq!(pkt1.ma_seq, 1);

    let pkt2 = engine.split_packet(500).expect("packet split");
    assert_eq!(pkt2.leg, AtsssAccessLeg::ThreeGppCellular);
    assert_eq!(pkt2.ma_seq, 2);

    let pkt3 = engine.split_packet(500).expect("packet split");
    assert_eq!(pkt3.leg, AtsssAccessLeg::NonThreeGppWifi);
    assert_eq!(pkt3.ma_seq, 3);

    // 2. Simulate 3GPP Cellular Leg Degradation/Failure -> Traffic falls back 100% to Wi-Fi
    engine.set_leg_health(AtsssAccessLeg::ThreeGppCellular, false);

    let pkt4 = engine.split_packet(500).expect("packet split");
    assert_eq!(pkt4.leg, AtsssAccessLeg::NonThreeGppWifi);
    assert_eq!(pkt4.ma_seq, 4);

    let pkt5 = engine.split_packet(500).expect("packet split");
    assert_eq!(pkt5.leg, AtsssAccessLeg::NonThreeGppWifi);
    assert_eq!(pkt5.ma_seq, 5);

    // 3. Restore Cellular Leg Health
    engine.set_leg_health(AtsssAccessLeg::ThreeGppCellular, true);
    let pkt6 = engine.split_packet(500).expect("packet split");
    assert_eq!(pkt6.leg, AtsssAccessLeg::ThreeGppCellular);
    assert_eq!(pkt6.ma_seq, 6);

    assert_eq!(engine.stats_3gpp.packets_forwarded, 3);
    assert_eq!(engine.stats_wifi.packets_forwarded, 3);
}

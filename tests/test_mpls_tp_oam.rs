use toy_tcpip::mpls_tp_oam::{
    GACH_CHANNEL_BFD_DIRECT, GACH_CHANNEL_DM, GACH_CHANNEL_IPV4_OAM, GACH_CHANNEL_IPV6_OAM,
    GACH_CHANNEL_LM, GACH_FIRST_NIBBLE, GACH_HEADER_LEN, GachHeader, MplsDelayMeasurementPdu,
    MplsLossMeasurementPdu, MplsTpOamEngine,
};

#[test]
fn test_gach_constants_and_types() {
    assert_eq!(GACH_FIRST_NIBBLE, 0x10);
    assert_eq!(GACH_HEADER_LEN, 4);
    assert_eq!(GACH_CHANNEL_IPV4_OAM, 0x0021);
    assert_eq!(GACH_CHANNEL_IPV6_OAM, 0x0057);
    assert_eq!(GACH_CHANNEL_BFD_DIRECT, 0x0007);
    assert_eq!(GACH_CHANNEL_LM, 0x0025);
    assert_eq!(GACH_CHANNEL_DM, 0x0026);

    let gach = GachHeader::new(GACH_CHANNEL_BFD_DIRECT);
    let bytes = gach.serialize();
    let parsed = GachHeader::parse(&bytes).unwrap();
    assert_eq!(parsed.channel_type, GACH_CHANNEL_BFD_DIRECT);

    let lm = MplsLossMeasurementPdu::new(1, 100, 99, 100, 99);
    let ser = lm.serialize();
    let parsed_lm = MplsLossMeasurementPdu::parse(&ser).unwrap();
    assert_eq!(parsed_lm.session_id, 1);
}

#[test]
fn test_mpls_tp_loss_measurement_engine_telemetry() {
    let mut node_a = MplsTpOamEngine::new(5555);
    let mut node_b = MplsTpOamEngine::new(5555);

    for _ in 0..10_000 {
        node_a.record_tx();
    }
    for _ in 0..9_995 {
        node_b.record_rx();
    }

    let (gach_q, lm_q) = node_a.create_lm_query();
    assert_eq!(gach_q.channel_type, GACH_CHANNEL_LM);

    let (gach_r, lm_r) = node_b.create_lm_reply(&lm_q);
    assert_eq!(gach_r.channel_type, GACH_CHANNEL_LM);

    let (lost, ratio) = lm_r.compute_forward_loss();
    assert_eq!(lost, 5);
    assert!((ratio - 0.0005).abs() < 1e-6);
}

#[test]
fn test_mpls_tp_delay_measurement_jitter_and_rtt() {
    let dm1 = MplsDelayMeasurementPdu::new(
        1001,
        (10, 0),
        (10, 2_000_000), // +2ms
        (10, 2_500_000), // +0.5ms residence
        (10, 4_500_000), // +2ms bwd -> RTT = 4ms (4_000_000 ns)
    );
    let dm2 = MplsDelayMeasurementPdu::new(
        1002,
        (11, 0),
        (11, 2_500_000), // +2.5ms
        (11, 3_000_000), // +0.5ms residence
        (11, 6_000_000), // +3ms bwd -> RTT = 5.5ms (5_500_000 ns)
    );

    let rtt1 = dm1.compute_two_way_delay_ns();
    let rtt2 = dm2.compute_two_way_delay_ns();

    assert_eq!(rtt1, 4_000_000);
    assert_eq!(rtt2, 5_500_000);

    let jitter_ns = rtt2.abs_diff(rtt1);
    assert_eq!(jitter_ns, 1_500_000); // 1.5ms jitter
}

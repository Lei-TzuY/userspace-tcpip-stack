//! Integration tests for BGP Flowspec IPv6 Action Extended Communities & Remarking Engine (RFC 8956 / RFC 8955).

use toy_tcpip::flowspec_v6_actions::{
    FS_ACTION_SUBTYPE_REDIRECT_RT, FS_ACTION_SUBTYPE_TRAFFIC_ACTION,
    FS_ACTION_SUBTYPE_TRAFFIC_MARKING, FS_ACTION_SUBTYPE_TRAFFIC_RATE, FlowspecV6ActionCommunity,
    FlowspecV6ActionEngine, FlowspecV6Verdict, TokenBucketLimiter,
};

#[test]
fn test_flowspec_v6_action_constants_and_encodings() {
    assert_eq!(FS_ACTION_SUBTYPE_TRAFFIC_RATE, 0x06);
    assert_eq!(FS_ACTION_SUBTYPE_TRAFFIC_ACTION, 0x07);
    assert_eq!(FS_ACTION_SUBTYPE_REDIRECT_RT, 0x08);
    assert_eq!(FS_ACTION_SUBTYPE_TRAFFIC_MARKING, 0x09);

    let action_terminal = FlowspecV6ActionCommunity::TrafficAction {
        terminal: true,
        sample: true,
    };
    let ser = action_terminal.serialize();
    assert_eq!(ser[0], 0x80);
    assert_eq!(ser[1], 0x07);
    assert_eq!(ser[7], 0x03); // terminal(0x01) | sample(0x02)

    let parsed = FlowspecV6ActionCommunity::parse(&ser).unwrap();
    assert_eq!(parsed, action_terminal);
}

#[test]
fn test_flowspec_v6_engine_mitigation_and_remarking() {
    let mut engine_remark = FlowspecV6ActionEngine::new();
    engine_remark.add_action(FlowspecV6ActionCommunity::TrafficMarking { dscp: 46 }); // DSCP EF (101110 -> 0x2E)

    let mut ipv6_pkt = vec![0x60, 0x00, 0x00, 0x00, 0, 10, 59, 64];
    ipv6_pkt.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    ipv6_pkt.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    ipv6_pkt.extend_from_slice(b"CriticalVoIPTraffic");

    let verdict1 = engine_remark.apply_actions(ipv6_pkt.clone());
    match verdict1 {
        FlowspecV6Verdict::Remarked { new_dscp, packet } => {
            assert_eq!(new_dscp, 46);
            let tc = ((packet[0] & 0x0F) << 4) | (packet[1] >> 4);
            assert_eq!(tc >> 2, 46);
        }
        other => panic!("Expected Remarked DSCP 46, got {:?}", other),
    }

    // Rate = 0 discard action
    let mut engine_drop = FlowspecV6ActionEngine::new();
    engine_drop.add_action(FlowspecV6ActionCommunity::TrafficRate {
        rate_bytes_sec: 0.0,
    });

    let verdict2 = engine_drop.apply_actions(ipv6_pkt);
    match verdict2 {
        FlowspecV6Verdict::Drop { .. } => {}
        other => panic!("Expected Drop for rate 0, got {:?}", other),
    }
}

#[test]
fn test_flowspec_v6_token_bucket_policer() {
    // 10,000 Bytes/sec, burst capacity 2,000 Bytes
    let mut limiter = TokenBucketLimiter::new(10_000.0, 2_000.0);

    // First packet 1500 bytes -> Admitted
    assert!(limiter.admit_packet(1500, 1_000_000_000));

    // Second packet 1500 bytes immediately -> Rejected (only 500 bytes left)
    assert!(!limiter.admit_packet(1500, 1_000_000_000));

    // After 0.15s (150ms = 150_000_000ns) -> Replenished 1500 bytes -> Admitted
    assert!(limiter.admit_packet(1500, 1_150_000_000));
}

//! Integration tests for EVPN Layer 2 Multicast IGMPv3/MLDv2 Join Suppression Engine.

use toy_tcpip::evpn_igmp_join_suppress::{EvpnIgmpJoinSuppressEngine, JoinSuppressVerdict};
use toy_tcpip::ipv4::Ipv4Address;

#[test]
fn test_evpn_igmp_join_suppress_integration() {
    let mut engine = EvpnIgmpJoinSuppressEngine::new();
    let src = Ipv4Address::new(192, 168, 1, 100);
    let grp = Ipv4Address::new(232, 1, 1, 1);

    // 10 hosts join the same channel
    for i in 1..=10 {
        let host = Ipv4Address::new(10, 0, 0, i);
        let v = engine.process_join(100, 1, src, grp, host);
        if i == 1 {
            assert!(matches!(
                v,
                JoinSuppressVerdict::FirstSubscriberProxyJoin { .. }
            ));
        } else {
            assert!(matches!(
                v,
                JoinSuppressVerdict::DuplicateJoinSuppressed { .. }
            ));
        }
    }

    assert_eq!(engine.total_joins_received, 10);
    assert_eq!(engine.total_joins_suppressed, 9);
    assert_eq!(engine.total_proxy_joins_sent, 1);
    assert!(engine.is_proxy_joined(100, 1, src, grp));
}

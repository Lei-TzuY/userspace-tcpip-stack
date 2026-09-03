// tests/test_evpn_igmp_explicit_tracking.rs

use toy_tcpip::evpn_igmp_explicit_tracking::{
    DEFAULT_EXPLICIT_TRACKING_TIMEOUT_SECS, EvpnIgmpExplicitTrackingEngine, ExplicitTrackingVerdict,
};
use toy_tcpip::ipv4::Ipv4Address;

#[test]
fn test_evpn_igmp_explicit_tracking_integration() {
    let mut engine = EvpnIgmpExplicitTrackingEngine::new(30);
    let src = Ipv4Address::new(192, 168, 50, 1);
    let grp = Ipv4Address::new(232, 10, 10, 10);
    let h1 = Ipv4Address::new(172, 16, 0, 1);
    let h2 = Ipv4Address::new(172, 16, 0, 2);

    // 1. Host 1 sends IGMPv3 Join on VNI 200, Port 5
    let v1 = engine.process_membership_report(200, 5, src, grp, h1, 100);
    assert_eq!(
        v1,
        ExplicitTrackingVerdict::SubscriberAdded {
            vni: 200,
            port_id: 5,
            source_ip: src,
            group_ip: grp,
            host_ip: h1,
            total_subscribers: 1,
            smet_advertise: true,
        }
    );
    assert!(engine.is_port_forwarding(200, 5, src, grp));

    // 2. Host 1 refreshes Membership Report
    let v_ref = engine.process_membership_report(200, 5, src, grp, h1, 110);
    assert_eq!(
        v_ref,
        ExplicitTrackingVerdict::SubscriberRefreshed {
            vni: 200,
            port_id: 5,
            source_ip: src,
            group_ip: grp,
            host_ip: h1,
        }
    );

    // 3. Host 2 sends Join on same Port
    let v2 = engine.process_membership_report(200, 5, src, grp, h2, 115);
    assert_eq!(
        v2,
        ExplicitTrackingVerdict::SubscriberAdded {
            vni: 200,
            port_id: 5,
            source_ip: src,
            group_ip: grp,
            host_ip: h2,
            total_subscribers: 2,
            smet_advertise: false,
        }
    );

    // 4. Host 1 sends Leave -> Port still forwards to Host 2
    let v_leave1 = engine.process_leave_group(200, 5, src, grp, h1);
    assert_eq!(
        v_leave1,
        ExplicitTrackingVerdict::SubscriberRemovedRemainingActive {
            vni: 200,
            port_id: 5,
            source_ip: src,
            group_ip: grp,
            leaving_host: h1,
            remaining_subscribers: 1,
        }
    );
    assert!(engine.is_port_forwarding(200, 5, src, grp));

    // 5. Host 2 sends Leave -> Fast Leave prunes Port immediately & triggers SMET withdrawal
    let v_leave2 = engine.process_leave_group(200, 5, src, grp, h2);
    assert_eq!(
        v_leave2,
        ExplicitTrackingVerdict::FastLeavePruned {
            vni: 200,
            port_id: 5,
            source_ip: src,
            group_ip: grp,
            leaving_host: h2,
            smet_withdraw: true,
        }
    );
    assert!(!engine.is_port_forwarding(200, 5, src, grp));

    assert_eq!(engine.total_reports_processed, 3);
    assert_eq!(engine.total_leaves_processed, 2);
    assert_eq!(engine.total_fast_leaves, 1);
    assert_eq!(engine.total_smet_advertisements, 1);
    assert_eq!(engine.total_smet_withdrawals, 1);
}

#[test]
fn test_default_timeout_constant() {
    assert_eq!(DEFAULT_EXPLICIT_TRACKING_TIMEOUT_SECS, 260);
}

use toy_tcpip::evpn_igmp_mld_snooping_filter::{
    EvpnMcastSnoopingFilterEngine, McastAclAction, McastFilterVerdict,
};
use toy_tcpip::ipv4::Ipv4Address;

#[test]
fn test_evpn_igmp_mld_snooping_filter_integration() {
    let mut engine = EvpnMcastSnoopingFilterEngine::new(3);

    // Rule: Deny all unapproved multicast groups in 239.0.0.0/8
    engine.add_rule(
        100,
        1,
        Ipv4Address::new(239, 0, 0, 0),
        Ipv4Address::new(239, 255, 255, 255),
        McastAclAction::Deny,
        "Deny organizational local scope multicast",
    );

    // 1. Join for blocked range -> Denied by ACL
    let v_acl = engine.evaluate_join(100, 1, Ipv4Address::new(239, 1, 1, 1));
    assert_eq!(
        v_acl,
        McastFilterVerdict::JoinDeniedByAcl {
            vni: 100,
            port_id: 1,
            group_ip: Ipv4Address::new(239, 1, 1, 1),
            reason: "Deny organizational local scope multicast".to_string(),
        }
    );

    // 2. Joins for permitted SSM ranges up to CAC limit (3 channels)
    let g1 = Ipv4Address::new(232, 1, 1, 1);
    let g2 = Ipv4Address::new(232, 1, 1, 2);
    let g3 = Ipv4Address::new(232, 1, 1, 3);
    let g4 = Ipv4Address::new(232, 1, 1, 4);

    let v1 = engine.evaluate_join(100, 1, g1);
    assert_eq!(
        v1,
        McastFilterVerdict::JoinPermitted {
            vni: 100,
            port_id: 1,
            group_ip: g1,
            current_active_channels: 1
        }
    );

    let v2 = engine.evaluate_join(100, 1, g2);
    assert_eq!(
        v2,
        McastFilterVerdict::JoinPermitted {
            vni: 100,
            port_id: 1,
            group_ip: g2,
            current_active_channels: 2
        }
    );

    let v3 = engine.evaluate_join(100, 1, g3);
    assert_eq!(
        v3,
        McastFilterVerdict::JoinPermitted {
            vni: 100,
            port_id: 1,
            group_ip: g3,
            current_active_channels: 3
        }
    );

    // 3. Fourth channel exceeds CAC quota -> Denied
    let v4 = engine.evaluate_join(100, 1, g4);
    assert_eq!(
        v4,
        McastFilterVerdict::JoinDeniedCacLimitReached {
            vni: 100,
            port_id: 1,
            group_ip: g4,
            max_limit: 3,
        }
    );

    // 4. Leave one channel -> CAC quota freed
    let v_leave = engine.process_leave(100, 1, g1);
    assert_eq!(
        v_leave,
        McastFilterVerdict::ChannelLeft {
            vni: 100,
            port_id: 1,
            group_ip: g1,
            remaining_channels: 2,
        }
    );

    // 5. Now fourth channel is admitted
    let v4_retry = engine.evaluate_join(100, 1, g4);
    assert_eq!(
        v4_retry,
        McastFilterVerdict::JoinPermitted {
            vni: 100,
            port_id: 1,
            group_ip: g4,
            current_active_channels: 3
        }
    );
}

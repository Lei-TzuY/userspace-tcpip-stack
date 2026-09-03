//! Integration tests for EVPN Layer 2 Multicast IGMP/MLD Snooping Querier Election Engine.

use toy_tcpip::evpn_igmp_querier_election::{
    EvpnIgmpQuerierElectionEngine, QuerierRole, QuerierVerdict,
};
use toy_tcpip::ipv4::Ipv4Address;

#[test]
fn test_evpn_igmp_querier_election_integration() {
    let pe_ip = Ipv4Address::new(172, 16, 0, 10);
    let mut engine = EvpnIgmpQuerierElectionEngine::new(pe_ip, 60, 10, 2);
    engine.register_vni(5001, 100);

    // Instance is active querier initially
    assert_eq!(engine.instances[0].role, QuerierRole::ActiveQuerier);

    // Initial startup query trigger
    let v_tick1 = engine.tick(115);
    assert_eq!(v_tick1.len(), 1);
    match &v_tick1[0] {
        QuerierVerdict::QueryDispatched {
            vni, is_startup, ..
        } => {
            assert_eq!(*vni, 5001);
            assert!(*is_startup);
        }
        _ => panic!("Expected QueryDispatched"),
    }

    // Peer with lower IP (172.16.0.5) sends query -> we yield role to NonQuerier
    let peer_ip = Ipv4Address::new(172, 16, 0, 5);
    let v_rx = engine.process_rx_query(5001, peer_ip, 120);
    match v_rx {
        QuerierVerdict::ElectedNonQuerier {
            vni,
            active_querier_ip,
            ..
        } => {
            assert_eq!(vni, 5001);
            assert_eq!(active_querier_ip, peer_ip);
        }
        _ => panic!("Expected ElectedNonQuerier"),
    }
    assert_eq!(engine.instances[0].role, QuerierRole::NonQuerier);

    // Peer fails to send keepalive query for > 125s (120 + 125 = 245s)
    let v_failover = engine.tick(250);
    assert_eq!(v_failover.len(), 1);
    match &v_failover[0] {
        QuerierVerdict::FailoverToActiveQuerier { vni, local_ip } => {
            assert_eq!(*vni, 5001);
            assert_eq!(*local_ip, pe_ip);
        }
        _ => panic!("Expected FailoverToActiveQuerier"),
    }
    assert_eq!(engine.instances[0].role, QuerierRole::ActiveQuerier);
}

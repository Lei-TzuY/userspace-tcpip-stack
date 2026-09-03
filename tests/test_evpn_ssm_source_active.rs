// tests/test_evpn_ssm_source_active.rs

use toy_tcpip::evpn_ssm_source_active::{
    DEFAULT_SOURCE_INACTIVITY_TIMEOUT_SECS, EvpnSourceActiveEngine, SourceActiveVerdict,
};
use toy_tcpip::ipv4::Ipv4Address;

#[test]
fn test_evpn_ssm_source_active_lifecycle() {
    let pe1_ip = Ipv4Address::new(10, 0, 0, 1);
    let pe2_ip = Ipv4Address::new(10, 0, 0, 2);

    let mut engine_pe1 = EvpnSourceActiveEngine::new(pe1_ip, 45);
    let mut engine_pe2 = EvpnSourceActiveEngine::new(pe2_ip, 45);

    let vni = 500;
    let esi = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];
    let source_ip = Ipv4Address::new(172, 16, 1, 100);
    let group_ip = Ipv4Address::new(232, 5, 5, 5);

    // 1. Source starts emitting traffic on PE1
    let v_adv = engine_pe1.record_source_traffic(vni, esi, source_ip, group_ip, 500);
    let sa_route = match v_adv {
        SourceActiveVerdict::AdvertiseSourceActive { route } => {
            assert_eq!(route.vni, vni);
            assert_eq!(route.source_ip, source_ip);
            assert_eq!(route.group_ip, group_ip);
            assert_eq!(route.originator_router_ip, pe1_ip);
            route
        }
        _ => panic!("Expected AdvertiseSourceActive"),
    };

    // 2. PE2 learns SA Route from PE1
    engine_pe2.learn_remote_sa_route(sa_route.clone(), 501);
    let loc_pe2 = engine_pe2.query_source_location(vni, source_ip, group_ip, 510);
    assert_eq!(
        loc_pe2,
        SourceActiveVerdict::ActiveSourceLocated {
            originator_router_ip: pe1_ip,
            esi,
            uptime_secs: 9,
        }
    );

    // 3. Source keeps streaming on PE1 at t = 530
    let v_ref = engine_pe1.record_source_traffic(vni, esi, source_ip, group_ip, 530);
    assert_eq!(
        v_ref,
        SourceActiveVerdict::SourceRefreshed {
            vni,
            source_ip,
            group_ip,
            last_seen_secs: 530,
        }
    );

    // 4. At t = 560 (30s since last seen <= 45s), no withdrawal
    let w_none = engine_pe1.check_aging(560);
    assert!(w_none.is_empty());

    // 5. At t = 580 (50s since last seen > 45s timeout), SA route is withdrawn
    let w_withdrawn = engine_pe1.check_aging(580);
    assert_eq!(w_withdrawn.len(), 1);
    match &w_withdrawn[0] {
        SourceActiveVerdict::WithdrawSourceActive { route, .. } => {
            assert_eq!(route.source_ip, source_ip);
            assert_eq!(route.group_ip, group_ip);
        }
        _ => panic!("Expected WithdrawSourceActive"),
    }

    assert_eq!(engine_pe1.total_sources_discovered, 1);
    assert_eq!(engine_pe1.total_sa_routes_advertised, 1);
    assert_eq!(engine_pe1.total_sa_routes_withdrawn, 1);
}

#[test]
fn test_default_timeout_constant() {
    assert_eq!(DEFAULT_SOURCE_INACTIVITY_TIMEOUT_SECS, 180);
}

//! Integration tests for EVPN L3 ESI Fast Mass-Withdrawal for Type 5 IP Prefix Routes (RFC 9136 / RFC 7432).

use toy_tcpip::evpn::RouteDistinguisher;
use toy_tcpip::evpn_l3_esi_mass_withdraw::{
    EvpnL3EsiFastWithdrawEngine, EvpnL3ForwardingState, EvpnL3PrefixKey, EvpnType5EsiRoute,
};
use toy_tcpip::evpn_mass_withdraw::EvpnPerEsAdRoute;
use toy_tcpip::evpn_synch::EthernetSegmentId;
use toy_tcpip::ipv4::Ipv4Address;

#[test]
fn test_evpn_l3_esi_mass_withdrawal_end_to_end() {
    let mut engine = EvpnL3EsiFastWithdrawEngine::new();

    let esi_site_a =
        EthernetSegmentId([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A]);
    let pe_alpha = Ipv4Address::new(172, 16, 0, 1);
    let pe_beta = Ipv4Address::new(172, 16, 0, 2);

    let rd = RouteDistinguisher::new(pe_alpha, 1);

    // Both PEs advertise EAD-per-ES (Route Type 1)
    engine.handle_ad_route_advertisement(&EvpnPerEsAdRoute::new(rd.clone(), esi_site_a, pe_alpha));
    engine.handle_ad_route_advertisement(&EvpnPerEsAdRoute::new(rd.clone(), esi_site_a, pe_beta));

    // Register 3 customer subnet prefixes bound to site A
    for i in 1..=3 {
        let key = EvpnL3PrefixKey {
            vrf_id: 100,
            prefix: Ipv4Address::new(10, 50, i, 0),
            prefix_len: 24,
        };
        engine.add_type5_esi_route(EvpnType5EsiRoute {
            rd: rd.clone(),
            key,
            esi: esi_site_a,
            vni: 70000,
            primary_pe: pe_alpha,
            backup_pe: Some(pe_beta),
        });
    }

    let test_key = EvpnL3PrefixKey {
        vrf_id: 100,
        prefix: Ipv4Address::new(10, 50, 2, 0),
        prefix_len: 24,
    };

    // Prior to link failure: routes forward to PE Alpha
    assert_eq!(
        engine.resolve_prefix_forwarding(&test_key),
        EvpnL3ForwardingState::ActivePrimary(pe_alpha)
    );

    // PE Alpha link failure -> Type 1 Mass Withdrawal
    let affected = engine.handle_ad_route_withdrawal(&esi_site_a, &pe_alpha);
    assert_eq!(affected, 3);

    // Instant failover to PE Beta for all 3 prefixes
    assert_eq!(
        engine.resolve_prefix_forwarding(&test_key),
        EvpnL3ForwardingState::FailedOverBackup(pe_beta)
    );
}

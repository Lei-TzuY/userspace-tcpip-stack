//! Integration tests for EVPN Route Type 4 (Ethernet Segment Route) & DF Election (RFC 7432).

use toy_tcpip::evpn_type4::{
    EVPN_ROUTE_TYPE_ETHERNET_SEGMENT, EthernetSegmentId as EsId, EvpnDfElection, EvpnType4Route,
};
use toy_tcpip::ipv4::Ipv4Address;

#[test]
fn test_evpn_type4_route_serialization_and_parsing() {
    let rd = [0x00, 0x01, 192, 168, 1, 1, 0, 10];
    let esi = EsId::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a]);
    let origin_ip = Ipv4Address([192, 0, 2, 50]);

    let type4 = EvpnType4Route::new(rd, esi, origin_ip);
    let bytes = type4.serialize();

    assert_eq!(bytes[0], EVPN_ROUTE_TYPE_ETHERNET_SEGMENT);
    assert_eq!(bytes[1], 21); // Length

    let parsed = EvpnType4Route::parse(&bytes).expect("Failed to parse EVPN Type 4 route");
    assert_eq!(parsed.route_distinguisher, rd);
    assert_eq!(parsed.esi, esi);
    assert_eq!(parsed.ip_address_length, 32);
    assert_eq!(parsed.originating_ip, origin_ip);
}

#[test]
fn test_evpn_df_election_candidate_addition_and_withdrawal() {
    let pe_local = Ipv4Address([10, 0, 0, 1]);
    let pe_remote1 = Ipv4Address([10, 0, 0, 2]);
    let pe_remote2 = Ipv4Address([10, 0, 0, 3]);

    let esi = EsId::new([0xEE; 10]);
    let mut election = EvpnDfElection::new(pe_local);

    election.attach_local_es(esi);
    election.handle_type4_route(&EvpnType4Route::new([0; 8], esi, pe_remote1));
    election.handle_type4_route(&EvpnType4Route::new([0; 8], esi, pe_remote2));

    // 3 candidates: [10.0.0.1 (0), 10.0.0.2 (1), 10.0.0.3 (2)]
    assert_eq!(election.elect_df(esi, 10), Some(pe_remote1)); // 10 % 3 = 1 -> pe_remote1
    assert_eq!(election.elect_df(esi, 12), Some(pe_local)); // 12 % 3 = 0 -> pe_local
    assert_eq!(election.elect_df(esi, 14), Some(pe_remote2)); // 14 % 3 = 2 -> pe_remote2

    // Now withdraw pe_remote1 (e.g. peer failure or interface down)
    election.withdraw_type4_route(esi, pe_remote1);

    // 2 candidates left: [10.0.0.1 (0), 10.0.0.3 (1)]
    assert_eq!(election.elect_df(esi, 10), Some(pe_local)); // 10 % 2 = 0 -> pe_local
    assert_eq!(election.elect_df(esi, 11), Some(pe_remote2)); // 11 % 2 = 1 -> pe_remote2
}

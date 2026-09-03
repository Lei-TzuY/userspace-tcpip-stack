//! Integration tests for SRv6 Mobile User Plane (MUP) Type 3 / Type 4 Route Extensions (draft-ietf-dmm-srv6-mobile-uplane).

use toy_tcpip::evpn::RouteDistinguisher;
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::Ipv6Address;
use toy_tcpip::srv6_mup_routing::{
    BGP_SAFI_MUP, MUP_ROUTE_TYPE_DIRECT, MUP_ROUTE_TYPE_DOWNLINK, MUP_ROUTE_TYPE_INTERWORK,
    MUP_ROUTE_TYPE_SESSION, MupRib, MupType1InterworkRoute, MupType2DirectRoute,
    MupType3DownlinkRoute, MupType4SessionRoute,
};

#[test]
fn test_mup_route_type_constants() {
    assert_eq!(BGP_SAFI_MUP, 85);
    assert_eq!(MUP_ROUTE_TYPE_INTERWORK, 1);
    assert_eq!(MUP_ROUTE_TYPE_DIRECT, 2);
    assert_eq!(MUP_ROUTE_TYPE_DOWNLINK, 3);
    assert_eq!(MUP_ROUTE_TYPE_SESSION, 4);
}

#[test]
fn test_mup_rib_full_lifecycle_and_handover() {
    let mut rib = MupRib::new();
    let rd = RouteDistinguisher {
        admin: 65001,
        assigned: 100,
    };

    let sid_gnodeb = Ipv6Address([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x01]);
    let sid_upf_dl = Ipv6Address([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20, 0x02]);
    let sid_pdu_session = Ipv6Address([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x30, 0x03]);

    // Add Type 1 (Interwork)
    rib.add_type1_route(MupType1InterworkRoute::new(
        rd.clone(),
        Ipv4Address::new(10, 100, 0, 0),
        16,
        0x50001,
        5,
        Ipv4Address::new(172, 16, 0, 1),
        sid_gnodeb,
    ));

    // Add Type 2 (Direct)
    rib.add_type2_route(MupType2DirectRoute::new(
        rd.clone(),
        Ipv4Address::new(10, 100, 1, 55),
        32,
        Ipv4Address::new(172, 16, 0, 2),
        sid_gnodeb,
    ));

    // Add Type 3 (Downlink TEID)
    rib.add_type3_route(MupType3DownlinkRoute::new(
        rd.clone(),
        Ipv4Address::new(172, 16, 0, 10),
        0x50001,
        5,
        sid_upf_dl,
    ));

    // Add Type 4 (Session Endpoint)
    rib.add_type4_route(MupType4SessionRoute::new(
        rd.clone(),
        Ipv4Address::new(172, 16, 0, 10),
        9999, // PDU Session ID
        2001, // TAC
        sid_pdu_session,
    ));

    // Assert resolutions
    assert_eq!(
        *rib.resolve_ue_sid(&rd, &Ipv4Address::new(10, 100, 1, 55))
            .unwrap(),
        sid_gnodeb
    );
    assert_eq!(*rib.resolve_downlink_sid(&rd, 0x50001).unwrap(), sid_upf_dl);
    assert_eq!(
        *rib.resolve_session_sid(&rd, 9999).unwrap(),
        sid_pdu_session
    );
}

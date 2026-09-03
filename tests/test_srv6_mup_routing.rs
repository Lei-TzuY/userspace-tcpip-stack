use toy_tcpip::evpn::RouteDistinguisher;
use toy_tcpip::srv6_mup_routing::{
    BGP_SAFI_MUP, MUP_ROUTE_TYPE_DIRECT, MUP_ROUTE_TYPE_INTERWORK, MupRib, MupType1InterworkRoute,
    MupType2DirectRoute,
};
use toy_tcpip::{Ipv4Address, Ipv6Address};

#[test]
fn test_mup_constants() {
    assert_eq!(BGP_SAFI_MUP, 85);
    assert_eq!(MUP_ROUTE_TYPE_INTERWORK, 1);
    assert_eq!(MUP_ROUTE_TYPE_DIRECT, 2);
}

#[test]
fn test_mup_type1_and_type2_codecs() {
    let rd = RouteDistinguisher {
        admin: 65000,
        assigned: 10,
    };
    let sid1 = Ipv6Address([0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let sid2 = Ipv6Address([0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

    // Type 1 test
    let t1 = MupType1InterworkRoute::new(
        rd.clone(),
        Ipv4Address::new(10, 0, 0, 0),
        24,
        0xDEADBEEF,
        5,
        Ipv4Address::new(192, 168, 1, 1),
        sid1,
    );
    let ser1 = t1.serialize();
    let parsed1 = MupType1InterworkRoute::parse(&ser1).expect("Valid Type 1 parse");
    assert_eq!(parsed1.teid, 0xDEADBEEF);
    assert_eq!(parsed1.qfi, 5);
    assert_eq!(parsed1.srv6_sid, sid1);

    // Type 2 test
    let t2 = MupType2DirectRoute::new(
        rd,
        Ipv4Address::new(10, 0, 0, 100),
        32,
        Ipv4Address::new(192, 168, 2, 2),
        sid2,
    );
    let ser2 = t2.serialize();
    let parsed2 = MupType2DirectRoute::parse(&ser2).expect("Valid Type 2 parse");
    assert_eq!(parsed2.ue_prefix, Ipv4Address::new(10, 0, 0, 100));
    assert_eq!(parsed2.srv6_sid, sid2);
}

#[test]
fn test_mup_rib_routing_steering() {
    let mut rib = MupRib::new();
    let rd = RouteDistinguisher {
        admin: 65000,
        assigned: 1,
    };

    let sid_cell1 = Ipv6Address([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1]);
    let sid_cell2 = Ipv6Address([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2]);

    rib.add_type2_route(MupType2DirectRoute::new(
        rd.clone(),
        Ipv4Address::new(10, 20, 0, 0),
        16,
        Ipv4Address::new(192, 168, 100, 1),
        sid_cell1,
    ));

    rib.add_type2_route(MupType2DirectRoute::new(
        rd.clone(),
        Ipv4Address::new(10, 20, 5, 10),
        32,
        Ipv4Address::new(192, 168, 200, 1),
        sid_cell2,
    ));

    // Specific UE match
    let ue_direct = rib
        .resolve_ue_sid(&rd, &Ipv4Address::new(10, 20, 5, 10))
        .unwrap();
    assert_eq!(*ue_direct, sid_cell2);

    // Aggregate subnet match
    let ue_subnet = rib
        .resolve_ue_sid(&rd, &Ipv4Address::new(10, 20, 99, 1))
        .unwrap();
    assert_eq!(*ue_subnet, sid_cell1);

    // Non-existent IP
    assert!(
        rib.resolve_ue_sid(&rd, &Ipv4Address::new(192, 168, 1, 1))
            .is_none()
    );
}

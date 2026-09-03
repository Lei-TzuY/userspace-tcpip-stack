use toy_tcpip::ipv6::Ipv6Address;
use toy_tcpip::ospfv3::{
    IP_PROTO_OSPFV3, OSPFV3_ALL_D_ROUTERS, OSPFV3_ALL_SPF_ROUTERS, OSPFV3_LSA_INTRA_AREA_PREFIX,
    OSPFV3_LSA_LINK, OSPFV3_LSA_ROUTER, OSPFV3_TYPE_HELLO, OSPFV3_VERSION, Ospfv3Header,
    Ospfv3HelloPacket, Ospfv3IntraAreaPrefixLsa, Ospfv3LinkLsa, Ospfv3LsaHeader, Ospfv3Lsdb,
    Ospfv3Prefix,
};

#[test]
fn test_ospfv3_constants_and_multicast_addrs() {
    assert_eq!(IP_PROTO_OSPFV3, 89);
    assert_eq!(OSPFV3_VERSION, 3);
    assert_eq!(
        OSPFV3_ALL_SPF_ROUTERS,
        Ipv6Address([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x05])
    );
    assert_eq!(
        OSPFV3_ALL_D_ROUTERS,
        Ipv6Address([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x06])
    );
}

#[test]
fn test_ospfv3_hello_packet_serialization() {
    let hello = Ospfv3HelloPacket {
        header: Ospfv3Header {
            version: OSPFV3_VERSION,
            msg_type: OSPFV3_TYPE_HELLO,
            packet_length: 0,
            router_id: 0x01010101,
            area_id: 0x00000000,
            checksum: 0,
            instance_id: 0,
            reserved: 0,
        },
        interface_id: 10,
        router_priority: 1,
        options: 0x000013,
        hello_interval: 10,
        dead_interval: 40,
        designated_router: 0x01010101,
        backup_designated_router: 0x02020202,
        neighbors: vec![0x02020202, 0x03030303],
    };

    let serialized = hello.serialize();
    let parsed = Ospfv3HelloPacket::parse(&serialized).expect("OSPFv3 hello parse");

    assert_eq!(parsed.header.router_id, 0x01010101);
    assert_eq!(parsed.interface_id, 10);
    assert_eq!(parsed.designated_router, 0x01010101);
    assert_eq!(parsed.backup_designated_router, 0x02020202);
    assert_eq!(parsed.neighbors.len(), 2);
    assert_eq!(parsed.neighbors[0], 0x02020202);
}

#[test]
fn test_ospfv3_multi_node_spf_ipv6_fib() {
    let mut lsdb = Ospfv3Lsdb::new();

    // Topology:
    // Router 1 (0x01) --cost 5--> Router 2 (0x02) --cost 15--> Router 3 (0x03)
    // Router 1 (0x01) --cost 30--> Router 3 (0x03) (sub-optimal path)
    lsdb.add_adjacency(0x01, 0x02, 5);
    lsdb.add_adjacency(0x02, 0x03, 15);
    lsdb.add_adjacency(0x01, 0x03, 30);

    // Link-LSA for R2 link-local: fe80::2
    lsdb.add_link_lsa(Ospfv3LinkLsa {
        header: Ospfv3LsaHeader {
            age: 0,
            lsa_type: OSPFV3_LSA_LINK,
            link_state_id: 1,
            adv_router: 0x02,
            sequence_number: 1,
            checksum: 0,
            length: 0,
        },
        router_priority: 1,
        options: 0,
        link_local_address: Ipv6Address([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
        prefixes: Vec::new(),
    });

    // Link-LSA for R3 link-local: fe80::3
    lsdb.add_link_lsa(Ospfv3LinkLsa {
        header: Ospfv3LsaHeader {
            age: 0,
            lsa_type: OSPFV3_LSA_LINK,
            link_state_id: 1,
            adv_router: 0x03,
            sequence_number: 1,
            checksum: 0,
            length: 0,
        },
        router_priority: 1,
        options: 0,
        link_local_address: Ipv6Address([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]),
        prefixes: Vec::new(),
    });

    // R3 advertises prefix 2001:db8:ffff::/64
    let r3_dest_prefix = Ipv6Address([
        0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    lsdb.add_intra_area_prefix_lsa(Ospfv3IntraAreaPrefixLsa {
        header: Ospfv3LsaHeader {
            age: 0,
            lsa_type: OSPFV3_LSA_INTRA_AREA_PREFIX,
            link_state_id: 1,
            adv_router: 0x03,
            sequence_number: 1,
            checksum: 0,
            length: 0,
        },
        ref_ls_type: OSPFV3_LSA_ROUTER,
        ref_link_state_id: 0,
        ref_adv_router: 0x03,
        prefixes: vec![Ospfv3Prefix {
            prefix_len: 64,
            prefix_options: 0,
            metric: 10,
            address: r3_dest_prefix,
        }],
    });

    // Calculate SPF from Router 1
    let routes = lsdb.compute_spf(0x01);
    assert_eq!(routes.len(), 1);

    let route = &routes[0];
    assert_eq!(route.destination, r3_dest_prefix);
    // Shortest path cost: 5 (R1->R2) + 15 (R2->R3) + 10 (prefix) = 30 vs (30 + 10 = 40)
    assert_eq!(route.metric, 30);
    // Next hop is R2's link-local address fe80::2
    assert_eq!(
        route.next_hop,
        Ipv6Address([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2])
    );
}

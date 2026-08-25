use std::str::FromStr;

use toy_tcpip::ethernet::{ETHERTYPE_IPV6, EthernetFrame, MacAddress};
use toy_tcpip::icmpv6::{
    ICMPV6_TYPE_ROUTER_ADVERT, ICMPV6_TYPE_ROUTER_SOLICIT, Icmpv6Packet, PrefixInformationOption,
    RouterAdvertisement, ipv6_multicast_mac, link_local_address, slaac_address,
};
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::{Ipv6Address, Ipv6Packet, NEXT_HEADER_ICMPV6};
use toy_tcpip::lab::{LabRouter, VirtualLab};
use toy_tcpip::router::RouteSource;
use toy_tcpip::stack::NetStackConfig;

fn ip6(text: &str) -> Ipv6Address {
    Ipv6Address::from_str(text).unwrap()
}

#[test]
fn router_solicitation_and_advertisement_codec_round_trip() {
    let host_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let router_mac = MacAddress([0x02, 0, 0, 0, 1, 1]);
    let rs_src = Ipv6Address::UNSPECIFIED;
    let rs_dst = Ipv6Address::LINK_LOCAL_ALL_ROUTERS;
    let rs = Icmpv6Packet::build_router_solicitation(rs_src, rs_dst, Some(host_mac));
    let parsed_rs = Icmpv6Packet::parse(rs_src, rs_dst, &rs, true).unwrap();
    assert_eq!(parsed_rs.msg_type, ICMPV6_TYPE_ROUTER_SOLICIT);
    assert_eq!(parsed_rs.payload.len(), 4, "unspecified RS must omit SLLA");
    assert_eq!(
        ipv6_multicast_mac(rs_dst),
        Some(MacAddress([0x33, 0x33, 0, 0, 0, 2]))
    );

    let ra_src = link_local_address(router_mac);
    let ra_dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let pio = PrefixInformationOption::new(ip6("2001:db8:1::"), 64, true, true, 3600, 1800);
    let ra = Icmpv6Packet::build_router_advertisement(
        ra_src,
        ra_dst,
        64,
        1800,
        &[pio],
        Some(router_mac),
    );
    let parsed = Icmpv6Packet::parse(ra_src, ra_dst, &ra, true).unwrap();
    assert_eq!(parsed.msg_type, ICMPV6_TYPE_ROUTER_ADVERT);
    let decoded = RouterAdvertisement::parse(&parsed).unwrap();
    assert_eq!(decoded.router_lifetime, 1800);
    assert_eq!(decoded.current_hop_limit, 64);
    assert_eq!(decoded.prefixes, vec![pio]);

    assert_eq!(
        slaac_address(pio.prefix, 64, host_mac),
        Some(ip6("2001:db8:1::211:22ff:fe33:4455"))
    );
}

#[test]
fn router_solicitation_configures_slaac_and_default_route_then_routes_ping6() {
    let mut lab = VirtualLab::new();
    lab.add_link("lan1");
    lab.add_link("lan2");

    let host_a_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let host_b_mac = MacAddress([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
    let router_lan1_mac = MacAddress([0x02, 0, 0, 0, 1, 1]);
    let router_lan2_mac = MacAddress([0x02, 0, 0, 0, 2, 1]);
    let router_lan1 = ip6("2001:db8:1::1");
    let router_lan2 = ip6("2001:db8:2::1");
    let host_b = ip6("2001:db8:2::2");

    lab.add_host(
        "host_a",
        "lan1",
        NetStackConfig {
            mac: host_a_mac,
            ip: Ipv4Address::new(10, 1, 0, 2),
            ipv6: None,
            subnet_mask: 24,
            gateway: None,
        },
    );
    lab.add_host(
        "host_b",
        "lan2",
        NetStackConfig {
            mac: host_b_mac,
            ip: Ipv4Address::new(10, 2, 0, 2),
            ipv6: None,
            subnet_mask: 24,
            gateway: None,
        },
    );
    lab.host_mut("host_b")
        .unwrap()
        .stack
        .configure_ipv6_interface(host_b, 64, Some(router_lan2));

    let mut router = LabRouter::new("r1");
    router.add_interface(
        "eth0",
        router_lan1_mac,
        Ipv4Address::new(10, 1, 0, 1),
        24,
        "lan1",
    );
    router.add_interface(
        "eth1",
        router_lan2_mac,
        Ipv4Address::new(10, 2, 0, 1),
        24,
        "lan2",
    );
    assert!(router.set_interface_ipv6("eth0", router_lan1, 64));
    assert!(router.set_interface_ipv6("eth1", router_lan2, 64));
    lab.add_router(router);

    let rs = lab.host("host_a").unwrap().stack.router_solicitation();
    let rs_eth = EthernetFrame::parse(&rs).unwrap();
    assert_eq!(rs_eth.ethertype, toy_tcpip::ethernet::EtherType::IPv6);
    assert_eq!(
        rs_eth.dst_mac,
        MacAddress([0x33, 0x33, 0, 0, 0, 2]),
        "RS must use the RFC 2464 all-routers multicast MAC"
    );
    let rs_ip = Ipv6Packet::parse(rs_eth.payload).unwrap();
    assert_eq!(rs_ip.header.hop_limit, 255);
    assert_eq!(rs_ip.header.src_ip, Ipv6Address::UNSPECIFIED);

    lab.send_from_host("host_a", rs);
    lab.run_until_quiescent(20);

    let expected_a = ip6("2001:db8:1::211:22ff:fe33:4455");
    let router_ll = link_local_address(router_lan1_mac);
    let host_a = &lab.host("host_a").unwrap().stack;
    assert_eq!(host_a.config.ipv6, Some(expected_a));
    assert_eq!(host_a.ipv6_prefix_len(), Some(64));
    assert_eq!(host_a.ipv6_gateway(), Some(router_ll));
    assert_eq!(host_a.ndp_table.lookup(&router_ll), Some(router_lan1_mac));

    let connected = host_a
        .ipv6_routing_table
        .lookup(ip6("2001:db8:1::beef"))
        .unwrap();
    assert_eq!(connected.source, RouteSource::Connected);
    assert_eq!(connected.gateway, None);
    let remote = host_a.ipv6_routing_table.lookup(host_b).unwrap();
    assert_eq!(remote.gateway, Some(router_ll));

    let ping = lab
        .host_mut("host_a")
        .unwrap()
        .stack
        .ping6(host_b, 0x4862, 1, b"slaac-routed")
        .unwrap();
    lab.send_from_host("host_a", ping);
    lab.run_until_quiescent(60);

    assert_eq!(
        lab.host("host_a").unwrap().stack.received_icmpv6_replies,
        vec![(host_b, 0x4862, 1)]
    );
}

#[test]
fn host_ignores_router_advertisement_with_wrong_hop_limit() {
    let mut lab = VirtualLab::new();
    lab.add_link("lan");
    let host_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    lab.add_host(
        "host",
        "lan",
        NetStackConfig {
            mac: host_mac,
            ip: Ipv4Address::new(10, 0, 0, 2),
            ipv6: None,
            subnet_mask: 24,
            gateway: None,
        },
    );

    let router_mac = MacAddress([0x02, 0, 0, 0, 1, 1]);
    let src = link_local_address(router_mac);
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let pio = PrefixInformationOption::new(ip6("2001:db8:9::"), 64, true, true, 3600, 1800);
    let ra = Icmpv6Packet::build_router_advertisement(src, dst, 64, 1800, &[pio], Some(router_mac));
    let packet = Ipv6Packet::serialize(src, dst, NEXT_HEADER_ICMPV6, 64, &ra);
    let frame = EthernetFrame::serialize(
        ipv6_multicast_mac(dst).unwrap(),
        router_mac,
        ETHERTYPE_IPV6,
        &packet,
    );
    let responses = lab.host_mut("host").unwrap().stack.process_frame(&frame);
    assert!(responses.is_empty());
    assert_eq!(lab.host("host").unwrap().stack.config.ipv6, None);
}

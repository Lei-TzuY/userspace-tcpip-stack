use std::str::FromStr;

use toy_tcpip::bgp_caps::AfiSafi;
use toy_tcpip::bgp_ipv6::Ipv6Prefix;
use toy_tcpip::bgp_router::{BgpPeerMode, BgpState};
use toy_tcpip::ethernet::{ETHERTYPE_IPV6, EthernetFrame, MacAddress};
use toy_tcpip::icmpv6::{ICMPV6_TYPE_TIME_EXCEEDED, Icmpv6Packet};
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::{Ipv6Address, Ipv6Packet, NEXT_HEADER_ICMPV6};
use toy_tcpip::lab::{LabRouter, VirtualLab};
use toy_tcpip::router::RouteSource;
use toy_tcpip::stack::NetStackConfig;

fn ip6(s: &str) -> Ipv6Address {
    Ipv6Address::from_str(s).unwrap()
}

fn mac(a: u8, b: u8) -> MacAddress {
    MacAddress([0x02, 0, 0, 0, a, b])
}

#[test]
fn lab_router_forwards_ipv6_between_subnets_with_cold_ndp() {
    let mut lab = VirtualLab::new();
    lab.add_link("lan1");
    lab.add_link("lan2");

    let host_a = ip6("2001:db8:1::2");
    let host_b = ip6("2001:db8:2::2");
    let gw_a = ip6("2001:db8:1::1");
    let gw_b = ip6("2001:db8:2::1");

    lab.add_host(
        "host_a",
        "lan1",
        NetStackConfig {
            mac: mac(0x0a, 2),
            ip: Ipv4Address::new(10, 1, 0, 2),
            ipv6: Some(host_a),
            subnet_mask: 24,
            gateway: None,
        },
    );
    lab.add_host(
        "host_b",
        "lan2",
        NetStackConfig {
            mac: mac(0x0b, 2),
            ip: Ipv4Address::new(10, 2, 0, 2),
            ipv6: Some(host_b),
            subnet_mask: 24,
            gateway: None,
        },
    );
    lab.host_mut("host_a")
        .unwrap()
        .stack
        .ipv6_routing_table
        .add_route(Ipv6Address::UNSPECIFIED, 0, Some(gw_a), "eth0");
    lab.host_mut("host_b")
        .unwrap()
        .stack
        .ipv6_routing_table
        .add_route(Ipv6Address::UNSPECIFIED, 0, Some(gw_b), "eth0");

    let mut router = LabRouter::new("r1");
    router.add_interface("eth0", mac(1, 0), Ipv4Address::new(10, 1, 0, 1), 24, "lan1");
    router.add_interface("eth1", mac(1, 1), Ipv4Address::new(10, 2, 0, 1), 24, "lan2");
    assert!(router.set_interface_ipv6("eth0", gw_a, 64));
    assert!(router.set_interface_ipv6("eth1", gw_b, 64));
    lab.add_router(router);

    let frame = lab
        .host_mut("host_a")
        .unwrap()
        .stack
        .ping6(host_b, 0x600d, 1, b"routed-v6")
        .unwrap();
    lab.send_from_host("host_a", frame);
    lab.run_until_quiescent(40);

    assert_eq!(
        lab.host("host_a").unwrap().stack.received_icmpv6_replies,
        vec![(host_b, 0x600d, 1)]
    );
    assert_eq!(
        lab.router("r1")
            .unwrap()
            .ndp_tables
            .get("eth0")
            .unwrap()
            .lookup(&host_a),
        Some(mac(0x0a, 2))
    );
    assert_eq!(
        lab.router("r1")
            .unwrap()
            .ndp_tables
            .get("eth1")
            .unwrap()
            .lookup(&host_b),
        Some(mac(0x0b, 2))
    );
}

#[test]
fn lab_router_returns_icmpv6_time_exceeded_at_hop_limit_one() {
    let mut router = LabRouter::new("r1");
    let ingress_mac = mac(1, 0);
    let host_mac = mac(0x0a, 2);
    let ingress_ip = ip6("2001:db8:1::1");
    let host_ip = ip6("2001:db8:1::2");
    router.add_interface(
        "eth0",
        ingress_mac,
        Ipv4Address::new(10, 1, 0, 1),
        24,
        "lan1",
    );
    router.set_interface_ipv6("eth0", ingress_ip, 64);

    let invoking = Ipv6Packet::serialize(host_ip, ip6("2001:db8:ffff::1"), 17, 1, b"ttl");
    let raw = EthernetFrame::serialize(ingress_mac, host_mac, ETHERTYPE_IPV6, &invoking);
    let out = router.process_incoming_frame("lan1", &raw);
    assert_eq!(out.len(), 1);
    let eth = EthernetFrame::parse(&out[0].1).unwrap();
    let ip = Ipv6Packet::parse(eth.payload).unwrap();
    assert_eq!(ip.header.src_ip, ingress_ip);
    assert_eq!(ip.header.dst_ip, host_ip);
    assert_eq!(ip.header.next_header, NEXT_HEADER_ICMPV6);
    let icmp = Icmpv6Packet::parse(ip.header.src_ip, ip.header.dst_ip, ip.payload, true).unwrap();
    assert_eq!(icmp.msg_type, ICMPV6_TYPE_TIME_EXCEEDED);
    assert_eq!(icmp.code, 0);
}

#[test]
fn bgp_learned_ipv6_routes_drive_real_two_as_ping6() {
    let mut lab = VirtualLab::new();
    for link in ["lan1", "transit", "lan2"] {
        lab.add_link(link);
    }

    let host_a = ip6("2001:db8:1::2");
    let host_b = ip6("2001:db8:2::2");
    let r1_lan = ip6("2001:db8:1::1");
    let r1_transit = ip6("2001:db8:12::1");
    let r2_transit = ip6("2001:db8:12::2");
    let r2_lan = ip6("2001:db8:2::1");

    lab.add_host(
        "host_a",
        "lan1",
        NetStackConfig {
            mac: mac(0x0a, 2),
            ip: Ipv4Address::new(10, 1, 0, 2),
            ipv6: Some(host_a),
            subnet_mask: 24,
            gateway: None,
        },
    );
    lab.add_host(
        "host_b",
        "lan2",
        NetStackConfig {
            mac: mac(0x0b, 2),
            ip: Ipv4Address::new(10, 2, 0, 2),
            ipv6: Some(host_b),
            subnet_mask: 24,
            gateway: None,
        },
    );
    lab.host_mut("host_a")
        .unwrap()
        .stack
        .ipv6_routing_table
        .add_route(Ipv6Address::UNSPECIFIED, 0, Some(r1_lan), "eth0");
    lab.host_mut("host_b")
        .unwrap()
        .stack
        .ipv6_routing_table
        .add_route(Ipv6Address::UNSPECIFIED, 0, Some(r2_lan), "eth0");

    let mut r1 = LabRouter::new("r1");
    r1.add_interface("lan", mac(1, 0), Ipv4Address::new(10, 1, 0, 1), 24, "lan1");
    r1.add_interface(
        "wan",
        mac(1, 1),
        Ipv4Address::new(10, 12, 0, 1),
        30,
        "transit",
    );
    r1.set_interface_ipv6("lan", r1_lan, 64);
    r1.set_interface_ipv6("wan", r1_transit, 64);
    r1.enable_bgp(65001, Ipv4Address::new(1, 1, 1, 1))
        .set_hold_time(9);
    r1.add_bgp_peer(
        Ipv4Address::new(10, 12, 0, 2),
        65002,
        Ipv4Address::new(10, 12, 0, 1),
        BgpPeerMode::Active,
    );
    {
        let bgp = r1.bgp_mut().unwrap();
        bgp.enable_family(AfiSafi::IPV6_UNICAST);
        bgp.set_ipv6_next_hop(r1_transit);
        bgp.originate_ipv6(Ipv6Prefix::new(ip6("2001:db8:1::"), 64), r1_lan);
    }

    let mut r2 = LabRouter::new("r2");
    r2.add_interface(
        "wan",
        mac(2, 0),
        Ipv4Address::new(10, 12, 0, 2),
        30,
        "transit",
    );
    r2.add_interface("lan", mac(2, 1), Ipv4Address::new(10, 2, 0, 1), 24, "lan2");
    r2.set_interface_ipv6("wan", r2_transit, 64);
    r2.set_interface_ipv6("lan", r2_lan, 64);
    r2.enable_bgp(65002, Ipv4Address::new(2, 2, 2, 2))
        .set_hold_time(9);
    r2.add_bgp_peer(
        Ipv4Address::new(10, 12, 0, 1),
        65001,
        Ipv4Address::new(10, 12, 0, 2),
        BgpPeerMode::Passive,
    );
    {
        let bgp = r2.bgp_mut().unwrap();
        bgp.enable_family(AfiSafi::IPV6_UNICAST);
        bgp.set_ipv6_next_hop(r2_transit);
        bgp.originate_ipv6(Ipv6Prefix::new(ip6("2001:db8:2::"), 64), r2_lan);
    }

    lab.add_router(r1);
    lab.add_router(r2);

    assert!(lab.run_until(50, 60_000, |l| {
        l.router("r1")
            .unwrap()
            .bgp()
            .unwrap()
            .peer(Ipv4Address::new(10, 12, 0, 2))
            .is_some_and(|p| p.state == BgpState::Established)
            && l.router("r2")
                .unwrap()
                .bgp()
                .unwrap()
                .peer(Ipv4Address::new(10, 12, 0, 1))
                .is_some_and(|p| p.state == BgpState::Established)
    }));
    assert!(lab.run_until(50, 20_000, |l| {
        !l.router("r1")
            .unwrap()
            .ipv6_routing_table
            .routes_from(RouteSource::Bgp)
            .is_empty()
            && !l
                .router("r2")
                .unwrap()
                .ipv6_routing_table
                .routes_from(RouteSource::Bgp)
                .is_empty()
    }));

    let frame = lab
        .host_mut("host_a")
        .unwrap()
        .stack
        .ping6(host_b, 0xb660, 7, b"bgp-data-plane")
        .unwrap();
    lab.send_from_host("host_a", frame);
    lab.run_until_quiescent(80);

    assert_eq!(
        lab.host("host_a").unwrap().stack.received_icmpv6_replies,
        vec![(host_b, 0xb660, 7)]
    );
}

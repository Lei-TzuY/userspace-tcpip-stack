use std::str::FromStr;

use toy_tcpip::ethernet::{ETHERTYPE_IPV6, EthernetFrame, MacAddress};
use toy_tcpip::icmpv6::{
    ICMPV6_TYPE_NEIGHBOR_ADVERT, Icmpv6Packet, ipv6_multicast_mac, slaac_address,
};
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::{Ipv6Address, Ipv6Packet, NEXT_HEADER_ICMPV6};
use toy_tcpip::lab::{LabRouter, VirtualLab};
use toy_tcpip::stack::{Ipv6DadStatus, NetStackConfig};

fn ip6(text: &str) -> Ipv6Address {
    Ipv6Address::from_str(text).unwrap()
}

fn router_with_ipv6(address: Ipv6Address, mac: MacAddress) -> LabRouter {
    let mut router = LabRouter::new("r1");
    router.add_interface("eth0", mac, Ipv4Address::new(10, 0, 0, 1), 24, "lan");
    assert!(router.set_interface_ipv6("eth0", address, 64));
    router
}

#[test]
fn router_defends_owned_address_against_dad_without_learning_unspecified_source() {
    let router_mac = MacAddress([0x02, 0, 0, 0, 1, 1]);
    let host_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let target = ip6("2001:db8:1::1");
    let mut router = router_with_ipv6(target, router_mac);

    let dst = target.solicited_node_multicast();
    let ns = Icmpv6Packet::build_dad_neighbor_solicitation(dst, target);
    let packet = Ipv6Packet::serialize(Ipv6Address::UNSPECIFIED, dst, NEXT_HEADER_ICMPV6, 255, &ns);
    let frame = EthernetFrame::serialize(
        ipv6_multicast_mac(dst).unwrap(),
        host_mac,
        ETHERTYPE_IPV6,
        &packet,
    );

    let transmissions = router.process_incoming_frame("lan", &frame);
    assert_eq!(transmissions.len(), 1);
    assert_eq!(transmissions[0].0, "lan");
    assert_eq!(
        router
            .ndp_tables
            .get("eth0")
            .and_then(|table| table.lookup(&Ipv6Address::UNSPECIFIED)),
        None,
        "DAD source :: must never enter the router NDP cache"
    );

    let eth = EthernetFrame::parse(&transmissions[0].1).unwrap();
    assert_eq!(
        eth.dst_mac,
        ipv6_multicast_mac(Ipv6Address::LINK_LOCAL_ALL_NODES).unwrap()
    );
    let ip = Ipv6Packet::parse(eth.payload).unwrap();
    assert_eq!(ip.header.src_ip, target);
    assert_eq!(ip.header.dst_ip, Ipv6Address::LINK_LOCAL_ALL_NODES);
    assert_eq!(ip.header.hop_limit, 255);
    let na = Icmpv6Packet::parse(ip.header.src_ip, ip.header.dst_ip, ip.payload, true).unwrap();
    assert_eq!(na.msg_type, ICMPV6_TYPE_NEIGHBOR_ADVERT);
    assert_eq!(
        na.payload[0] & 0x40,
        0,
        "DAD defence NA must be unsolicited"
    );
    assert_ne!(na.payload[0] & 0x80, 0, "router flag remains set");
    assert_ne!(
        na.payload[0] & 0x20,
        0,
        "owner may override stale cache state"
    );
    assert_eq!(&na.payload[4..20], &target.0);
}

#[test]
fn router_ignores_neighbor_solicitation_with_wrong_hop_limit() {
    let router_mac = MacAddress([0x02, 0, 0, 0, 1, 1]);
    let host_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let target = ip6("2001:db8:1::1");
    let mut router = router_with_ipv6(target, router_mac);
    let dst = target.solicited_node_multicast();
    let ns = Icmpv6Packet::build_dad_neighbor_solicitation(dst, target);
    let packet = Ipv6Packet::serialize(Ipv6Address::UNSPECIFIED, dst, NEXT_HEADER_ICMPV6, 64, &ns);
    let frame = EthernetFrame::serialize(
        ipv6_multicast_mac(dst).unwrap(),
        host_mac,
        ETHERTYPE_IPV6,
        &packet,
    );
    assert!(router.process_incoming_frame("lan", &frame).is_empty());
}

#[test]
fn normal_neighbor_solicitation_still_learns_source_and_returns_solicited_na() {
    let router_mac = MacAddress([0x02, 0, 0, 0, 1, 1]);
    let host_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let target = ip6("2001:db8:1::1");
    let host_ip = ip6("2001:db8:1::2");
    let mut router = router_with_ipv6(target, router_mac);

    let ns = Icmpv6Packet::build_neighbor_solicitation(host_ip, target, target, host_mac);
    let packet = Ipv6Packet::serialize(host_ip, target, NEXT_HEADER_ICMPV6, 255, &ns);
    let frame = EthernetFrame::serialize(router_mac, host_mac, ETHERTYPE_IPV6, &packet);
    let transmissions = router.process_incoming_frame("lan", &frame);
    assert_eq!(transmissions.len(), 1);
    assert_eq!(
        router.ndp_tables.get("eth0").unwrap().lookup(&host_ip),
        Some(host_mac)
    );
    let eth = EthernetFrame::parse(&transmissions[0].1).unwrap();
    assert_eq!(eth.dst_mac, host_mac);
    let ip = Ipv6Packet::parse(eth.payload).unwrap();
    assert_eq!(ip.header.dst_ip, host_ip);
    let na = Icmpv6Packet::parse(ip.header.src_ip, ip.header.dst_ip, ip.payload, true).unwrap();
    assert_ne!(na.payload[0] & 0x40, 0, "ordinary NA remains solicited");
}

#[test]
fn slaac_dad_detects_collision_with_router_interface_address_end_to_end() {
    let mut lab = VirtualLab::new();
    lab.add_link("lan");
    let host_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let router_mac = MacAddress([0x02, 0, 0, 0, 1, 1]);
    let prefix = ip6("2001:db8:55::");
    let collision = slaac_address(prefix, 64, host_mac).unwrap();

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
    lab.add_router(router_with_ipv6(collision, router_mac));

    let rs = lab.host("host").unwrap().stack.router_solicitation();
    lab.send_from_host("host", rs);
    lab.run_until_quiescent(50);

    assert_eq!(
        lab.host("host").unwrap().stack.ipv6_dad_status(),
        Ipv6DadStatus::Duplicate(collision),
        "router-owned SLAAC candidate must fail DAD"
    );
    assert_eq!(lab.host("host").unwrap().stack.config.ipv6, None);
    assert_eq!(
        lab.router("r1")
            .unwrap()
            .ndp_tables
            .get("eth0")
            .and_then(|table| table.lookup(&Ipv6Address::UNSPECIFIED)),
        None
    );

    lab.advance_time(1_000);
    lab.run_until_quiescent(20);
    assert_eq!(lab.host("host").unwrap().stack.config.ipv6, None);
}

use std::str::FromStr;

use toy_tcpip::ethernet::{ETHERTYPE_IPV6, EthernetFrame, MacAddress};
use toy_tcpip::icmpv6::{Icmpv6Packet, ipv6_multicast_mac, link_local_address};
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::{Ipv6Address, Ipv6Packet, NEXT_HEADER_ICMPV6};
use toy_tcpip::stack::{NetStack, NetStackConfig};

fn ip6(text: &str) -> Ipv6Address {
    Ipv6Address::from_str(text).unwrap()
}

fn host(host_mac: MacAddress, host_ip: Ipv6Address, gateway: Option<Ipv6Address>) -> NetStack {
    let mut stack = NetStack::new(NetStackConfig {
        mac: host_mac,
        ip: Ipv4Address::new(192, 0, 2, 2),
        ipv6: None,
        subnet_mask: 24,
        gateway: None,
    });
    stack.configure_ipv6_interface(host_ip, 64, gateway);
    stack
}

#[test]
fn ordinary_routed_ipv6_data_does_not_create_a_fake_neighbor() {
    let host_mac = MacAddress([0x02, 0, 0, 0, 1, 2]);
    let router_mac = MacAddress([0x02, 0, 0, 0, 1, 1]);
    let host_ip = ip6("2001:db8:10::2");
    let remote = ip6("2001:db8:ffff::9");
    let mut stack = host(host_mac, host_ip, None);

    let echo = Icmpv6Packet::build_echo_request(remote, host_ip, 0x600d, 3, b"routed");
    let packet = Ipv6Packet::serialize(remote, host_ip, NEXT_HEADER_ICMPV6, 63, &echo);
    let frame = EthernetFrame::serialize(host_mac, router_mac, ETHERTYPE_IPV6, &packet);
    let replies = stack.process_frame(&frame);

    assert_eq!(replies.len(), 1, "ordinary IPv6 delivery must still work");
    assert_eq!(
        stack.ndp_table.lookup(&remote),
        None,
        "a remote IPv6 source behind a router is not an L2 neighbour"
    );
    assert_eq!(
        EthernetFrame::parse(&replies[0]).unwrap().dst_mac,
        router_mac
    );
}

#[test]
fn valid_router_advertisement_learns_only_the_on_link_router() {
    let host_mac = MacAddress([0x02, 0, 0, 0, 2, 2]);
    let router_mac = MacAddress([0x02, 0, 0, 0, 2, 1]);
    let host_ip = ip6("2001:db8:20::2");
    let router_ip = link_local_address(router_mac);
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let mut stack = host(host_mac, host_ip, None);

    let ra = Icmpv6Packet::build_router_advertisement(router_ip, dst, 64, 0, &[], Some(router_mac));
    let packet = Ipv6Packet::serialize(router_ip, dst, NEXT_HEADER_ICMPV6, 255, &ra);
    let frame = EthernetFrame::serialize(
        ipv6_multicast_mac(dst).unwrap(),
        router_mac,
        ETHERTYPE_IPV6,
        &packet,
    );

    assert!(stack.process_frame(&frame).is_empty());
    assert_eq!(stack.ndp_table.lookup(&router_ip), Some(router_mac));
}

#[test]
fn valid_neighbor_solicitation_learns_its_non_dad_source() {
    let host_mac = MacAddress([0x02, 0, 0, 0, 3, 2]);
    let peer_mac = MacAddress([0x02, 0, 0, 0, 3, 3]);
    let host_ip = ip6("2001:db8:30::2");
    let peer_ip = ip6("2001:db8:30::3");
    let mut stack = host(host_mac, host_ip, None);
    let dst = host_ip.solicited_node_multicast();
    let ns = Icmpv6Packet::build_neighbor_solicitation(peer_ip, dst, host_ip, peer_mac);
    let packet = Ipv6Packet::serialize(peer_ip, dst, NEXT_HEADER_ICMPV6, 255, &ns);
    let frame = EthernetFrame::serialize(
        ipv6_multicast_mac(dst).unwrap(),
        peer_mac,
        ETHERTYPE_IPV6,
        &packet,
    );

    let replies = stack.process_frame(&frame);
    assert_eq!(replies.len(), 1);
    assert_eq!(stack.ndp_table.lookup(&peer_ip), Some(peer_mac));
}

#[test]
fn valid_neighbor_advertisement_learns_target_and_releases_pending_packet() {
    let host_mac = MacAddress([0x02, 0, 0, 0, 4, 2]);
    let gateway_mac = MacAddress([0x02, 0, 0, 0, 4, 1]);
    let host_ip = ip6("2001:db8:40::2");
    let gateway = ip6("fe80::401");
    let remote = ip6("2001:db8:ffff::40");
    let mut stack = host(host_mac, host_ip, Some(gateway));

    let _ns = stack
        .ping6(remote, 0x4861, 1, b"queued")
        .expect("cold NDP must start resolution");
    assert_eq!(stack.ndp_table.lookup(&gateway), None);
    assert_eq!(
        stack.pending_ndp_packets.get(&gateway).map(Vec::len),
        Some(1)
    );

    let na = Icmpv6Packet::build_neighbor_advertisement(
        gateway,
        host_ip,
        gateway,
        gateway_mac,
        true,
        true,
        true,
    );
    let packet = Ipv6Packet::serialize(gateway, host_ip, NEXT_HEADER_ICMPV6, 255, &na);
    let frame = EthernetFrame::serialize(host_mac, gateway_mac, ETHERTYPE_IPV6, &packet);
    let released = stack.process_frame(&frame);

    assert_eq!(stack.ndp_table.lookup(&gateway), Some(gateway_mac));
    assert!(!stack.pending_ndp_packets.contains_key(&gateway));
    assert_eq!(released.len(), 1);
    assert_eq!(
        EthernetFrame::parse(&released[0]).unwrap().dst_mac,
        gateway_mac
    );
}

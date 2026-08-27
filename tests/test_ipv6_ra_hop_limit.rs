use std::str::FromStr;

use toy_tcpip::ethernet::{ETHERTYPE_IPV6, EthernetFrame, MacAddress};
use toy_tcpip::icmpv6::{Icmpv6Packet, NDP_DELAY_FIRST_PROBE_TIME_MS, ipv6_multicast_mac};
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::{Ipv6Address, Ipv6Packet, NEXT_HEADER_ICMPV6};
use toy_tcpip::stack::{IPV6_DEFAULT_HOP_LIMIT, NetStack, NetStackConfig};

fn ip6(text: &str) -> Ipv6Address {
    Ipv6Address::from_str(text).unwrap()
}

fn mac(last: u8) -> MacAddress {
    MacAddress([0x02, 0, 0, 0, 0, last])
}

fn host() -> NetStack {
    let mut stack = NetStack::new(NetStackConfig {
        mac: mac(0x10),
        ip: Ipv4Address::new(192, 0, 2, 10),
        ipv6: None,
        subnet_mask: 24,
        gateway: None,
    });
    stack.configure_ipv6_interface(ip6("2001:db8:1::10"), 64, None);
    stack
}

fn ra_frame(stack: &NetStack, current_hop_limit: u8, outer_hop_limit: u8) -> Vec<u8> {
    let router_ip = ip6("fe80::1");
    let router_mac = mac(0x01);
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let ra = Icmpv6Packet::build_router_advertisement(
        router_ip,
        dst,
        current_hop_limit,
        1800,
        &[],
        Some(router_mac),
    );
    let packet = Ipv6Packet::serialize(router_ip, dst, NEXT_HEADER_ICMPV6, outer_hop_limit, &ra);
    EthernetFrame::serialize(
        ipv6_multicast_mac(dst).unwrap(),
        router_mac,
        ETHERTYPE_IPV6,
        &packet,
    )
}

fn ipv6_from_frame(frame: &[u8]) -> Ipv6Packet<'_> {
    let eth = EthernetFrame::parse(frame).unwrap();
    Ipv6Packet::parse(eth.payload).unwrap()
}

#[test]
fn valid_ra_cur_hop_limit_drives_subsequent_ping6() {
    let mut stack = host();
    assert_eq!(stack.ipv6_default_hop_limit(), IPV6_DEFAULT_HOP_LIMIT);

    assert!(stack.process_frame(&ra_frame(&stack, 37, 255)).is_empty());
    assert_eq!(stack.ipv6_default_hop_limit(), 37);

    let peer = ip6("2001:db8:1::20");
    stack.ndp_table.insert(peer, mac(0x20));
    let frame = stack.ping6(peer, 0x4861, 1, b"hop-limit").unwrap();
    assert_eq!(ipv6_from_frame(&frame).header.hop_limit, 37);
}

#[test]
fn zero_cur_hop_limit_preserves_previously_learned_value() {
    let mut stack = host();
    assert!(stack.process_frame(&ra_frame(&stack, 41, 255)).is_empty());
    assert_eq!(stack.ipv6_default_hop_limit(), 41);

    assert!(stack.process_frame(&ra_frame(&stack, 0, 255)).is_empty());
    assert_eq!(stack.ipv6_default_hop_limit(), 41);
}

#[test]
fn invalid_ra_cannot_change_default_hop_limit() {
    let mut stack = host();
    assert!(stack.process_frame(&ra_frame(&stack, 22, 64)).is_empty());
    assert_eq!(stack.ipv6_default_hop_limit(), IPV6_DEFAULT_HOP_LIMIT);
}

#[test]
fn echo_reply_uses_ra_learned_default_hop_limit() {
    let mut stack = host();
    assert!(stack.process_frame(&ra_frame(&stack, 39, 255)).is_empty());

    let host_ip = ip6("2001:db8:1::10");
    let peer_ip = ip6("2001:db8:1::20");
    let peer_mac = mac(0x20);
    let echo = Icmpv6Packet::build_echo_request(peer_ip, host_ip, 7, 9, b"reply");
    let packet = Ipv6Packet::serialize(peer_ip, host_ip, NEXT_HEADER_ICMPV6, 64, &echo);
    let frame = EthernetFrame::serialize(stack.config.mac, peer_mac, ETHERTYPE_IPV6, &packet);

    let replies = stack.process_frame(&frame);
    assert_eq!(replies.len(), 1);
    assert_eq!(ipv6_from_frame(&replies[0]).header.hop_limit, 39);
}

#[test]
fn ndp_control_packets_remain_hop_limit_255_after_ra_update() {
    let mut stack = host();
    assert!(stack.process_frame(&ra_frame(&stack, 33, 255)).is_empty());

    let peer = ip6("2001:db8:1::30");
    let peer_mac = mac(0x30);
    stack.ndp_table.mark_stale(peer, peer_mac);
    let data = stack.ping6(peer, 1, 1, b"nud").unwrap();
    assert_eq!(ipv6_from_frame(&data).header.hop_limit, 33);

    let probes = stack.step_timers(NDP_DELAY_FIRST_PROBE_TIME_MS);
    assert_eq!(probes.len(), 1);
    assert_eq!(ipv6_from_frame(&probes[0]).header.hop_limit, 255);
}

#[test]
fn clearing_ipv6_interface_restores_implementation_default() {
    let mut stack = host();
    assert!(stack.process_frame(&ra_frame(&stack, 31, 255)).is_empty());
    assert_eq!(stack.ipv6_default_hop_limit(), 31);

    stack.clear_ipv6_interface();
    assert_eq!(stack.ipv6_default_hop_limit(), IPV6_DEFAULT_HOP_LIMIT);
}

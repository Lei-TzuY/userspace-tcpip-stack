use std::str::FromStr;

use toy_tcpip::ethernet::{ETHERTYPE_IPV6, EthernetFrame, MacAddress};
use toy_tcpip::icmpv6::{Icmpv6Packet, ipv6_multicast_mac, link_local_address};
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::{
    Ipv6Address, Ipv6Packet, NEXT_HEADER_ICMPV6, compute_ipv6_transport_checksum,
};
use toy_tcpip::lab::LabRouter;
use toy_tcpip::stack::{Ipv6RouterDiscoveryStatus, NetStack, NetStackConfig};

fn ip6(text: &str) -> Ipv6Address {
    Ipv6Address::from_str(text).unwrap()
}

fn mac(last: u8) -> MacAddress {
    MacAddress([0x02, 0, 0, 0, 0, last])
}

fn host(host_mac: MacAddress, host_ip: Ipv6Address) -> NetStack {
    let mut stack = NetStack::new(NetStackConfig {
        mac: host_mac,
        ip: Ipv4Address::new(192, 0, 2, 2),
        ipv6: None,
        subnet_mask: 24,
        gateway: None,
    });
    stack.configure_ipv6_interface(host_ip, 64, None);
    stack
}

fn router() -> LabRouter {
    let mut router = LabRouter::new("r1");
    router.add_interface(
        "eth0",
        mac(0x10),
        Ipv4Address::new(192, 0, 2, 1),
        24,
        "lan1",
    );
    assert!(router.set_interface_ipv6("eth0", ip6("2001:db8:1::1"), 64));
    router
}

fn without_ethernet_lla_option(
    mut message: Vec<u8>,
    src: Ipv6Address,
    dst: Ipv6Address,
) -> Vec<u8> {
    assert!(message.len() >= 32);
    message.truncate(24);
    message[2] = 0;
    message[3] = 0;
    let checksum = compute_ipv6_transport_checksum(src, dst, NEXT_HEADER_ICMPV6, &message);
    message[2..4].copy_from_slice(&checksum.to_be_bytes());
    message
}

fn ipv6_frame(
    frame_src: MacAddress,
    frame_dst: MacAddress,
    src: Ipv6Address,
    dst: Ipv6Address,
    icmp: &[u8],
) -> Vec<u8> {
    let packet = Ipv6Packet::serialize(src, dst, NEXT_HEADER_ICMPV6, 255, icmp);
    EthernetFrame::serialize(frame_dst, frame_src, ETHERTYPE_IPV6, &packet)
}

#[test]
fn host_ns_without_slla_replies_but_does_not_learn_ethernet_source() {
    let host_mac = mac(0x10);
    let wire_mac = mac(0x21);
    let host_ip = ip6("2001:db8:1::1");
    let peer_ip = ip6("2001:db8:1::2");
    let dst = host_ip.solicited_node_multicast();
    let mut stack = host(host_mac, host_ip);
    let ns = Icmpv6Packet::build_neighbor_solicitation(peer_ip, dst, host_ip, wire_mac);
    let ns = without_ethernet_lla_option(ns, peer_ip, dst);
    let frame = ipv6_frame(
        wire_mac,
        ipv6_multicast_mac(dst).unwrap(),
        peer_ip,
        dst,
        &ns,
    );

    let replies = stack.process_frame(&frame);
    assert_eq!(replies.len(), 1, "a valid NS still receives an NA");
    assert_eq!(stack.ndp_table.lookup(&peer_ip), None);
}

#[test]
fn host_ns_learns_slla_instead_of_enclosing_ethernet_source() {
    let host_mac = mac(0x10);
    let wire_mac = mac(0x21);
    let advertised_mac = mac(0x22);
    let host_ip = ip6("2001:db8:1::1");
    let peer_ip = ip6("2001:db8:1::2");
    let dst = host_ip.solicited_node_multicast();
    let mut stack = host(host_mac, host_ip);
    let ns = Icmpv6Packet::build_neighbor_solicitation(peer_ip, dst, host_ip, advertised_mac);
    let frame = ipv6_frame(
        wire_mac,
        ipv6_multicast_mac(dst).unwrap(),
        peer_ip,
        dst,
        &ns,
    );

    assert_eq!(stack.process_frame(&frame).len(), 1);
    assert_eq!(stack.ndp_table.lookup(&peer_ip), Some(advertised_mac));
}

#[test]
fn host_ra_without_slla_is_accepted_without_neighbor_learning() {
    let host_mac = mac(0x30);
    let wire_mac = mac(0x31);
    let host_ip = ip6("2001:db8:1::30");
    let router_ip = ip6("fe80::31");
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let mut stack = host(host_mac, host_ip);
    let _first_rs = stack.start_router_discovery();
    let ra = Icmpv6Packet::build_router_advertisement(router_ip, dst, 64, 0, &[], None);
    let frame = ipv6_frame(
        wire_mac,
        ipv6_multicast_mac(dst).unwrap(),
        router_ip,
        dst,
        &ra,
    );

    assert!(stack.process_frame(&frame).is_empty());
    assert_eq!(
        stack.ipv6_router_discovery_status(),
        Ipv6RouterDiscoveryStatus::Idle,
        "the valid RA must still complete Router Discovery"
    );
    assert_eq!(stack.ndp_table.lookup(&router_ip), None);
}

#[test]
fn host_ra_learns_advertised_slla_instead_of_ethernet_source() {
    let host_mac = mac(0x30);
    let wire_mac = mac(0x31);
    let advertised_mac = mac(0x32);
    let host_ip = ip6("2001:db8:1::30");
    let router_ip = ip6("fe80::32");
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let mut stack = host(host_mac, host_ip);
    let ra =
        Icmpv6Packet::build_router_advertisement(router_ip, dst, 64, 0, &[], Some(advertised_mac));
    let frame = ipv6_frame(
        wire_mac,
        ipv6_multicast_mac(dst).unwrap(),
        router_ip,
        dst,
        &ra,
    );

    assert!(stack.process_frame(&frame).is_empty());
    assert_eq!(stack.ndp_table.lookup(&router_ip), Some(advertised_mac));
}

#[test]
fn router_rs_without_slla_replies_but_does_not_learn_ethernet_source() {
    let mut router = router();
    let wire_mac = mac(0x41);
    let source = ip6("fe80::41");
    let dst = Ipv6Address::LINK_LOCAL_ALL_ROUTERS;
    let rs = Icmpv6Packet::build_router_solicitation(source, dst, None);
    let frame = ipv6_frame(wire_mac, ipv6_multicast_mac(dst).unwrap(), source, dst, &rs);

    let replies = router.process_incoming_frame("lan1", &frame);
    assert_eq!(replies.len(), 1, "the valid RS must still receive an RA");
    assert_eq!(router.ndp_tables["eth0"].lookup(&source), None);
}

#[test]
fn router_rs_learns_advertised_slla_instead_of_ethernet_source() {
    let mut router = router();
    let wire_mac = mac(0x41);
    let advertised_mac = mac(0x42);
    let source = ip6("fe80::42");
    let dst = Ipv6Address::LINK_LOCAL_ALL_ROUTERS;
    let rs = Icmpv6Packet::build_router_solicitation(source, dst, Some(advertised_mac));
    let frame = ipv6_frame(wire_mac, ipv6_multicast_mac(dst).unwrap(), source, dst, &rs);

    assert_eq!(router.process_incoming_frame("lan1", &frame).len(), 1);
    assert_eq!(
        router.ndp_tables["eth0"].lookup(&source),
        Some(advertised_mac)
    );
}

#[test]
fn router_ns_without_slla_replies_but_does_not_learn_ethernet_source() {
    let mut router = router();
    let wire_mac = mac(0x51);
    let source = ip6("2001:db8:1::51");
    let target = ip6("2001:db8:1::1");
    let dst = target.solicited_node_multicast();
    let ns = Icmpv6Packet::build_neighbor_solicitation(source, dst, target, wire_mac);
    let ns = without_ethernet_lla_option(ns, source, dst);
    let frame = ipv6_frame(wire_mac, ipv6_multicast_mac(dst).unwrap(), source, dst, &ns);

    let replies = router.process_incoming_frame("lan1", &frame);
    assert_eq!(replies.len(), 1, "the valid NS must still receive an NA");
    assert_eq!(router.ndp_tables["eth0"].lookup(&source), None);
}

#[test]
fn router_na_resolution_uses_tlla_for_cache_and_queued_frame() {
    let mut router = router();
    let router_ip = ip6("2001:db8:1::1");
    let target = ip6("2001:db8:1::61");
    let wire_mac = mac(0x61);
    let advertised_mac = mac(0x62);
    let queued = Ipv6Packet::serialize(router_ip, target, 59, 64, b"queued");
    router
        .pending_ipv6_transit_packets
        .insert(("eth0".to_string(), target), vec![queued]);

    let na = Icmpv6Packet::build_neighbor_advertisement(
        target,
        router_ip,
        target,
        advertised_mac,
        false,
        true,
        true,
    );
    let frame = ipv6_frame(wire_mac, mac(0x10), target, router_ip, &na);
    let released = router.process_incoming_frame("lan1", &frame);

    assert_eq!(
        router.ndp_tables["eth0"].lookup(&target),
        Some(advertised_mac)
    );
    assert!(
        !router
            .pending_ipv6_transit_packets
            .contains_key(&("eth0".to_string(), target))
    );
    assert_eq!(released.len(), 1);
    assert_eq!(
        EthernetFrame::parse(&released[0].1).unwrap().dst_mac,
        advertised_mac
    );
}

#[test]
fn router_na_without_tlla_cannot_complete_incomplete_resolution() {
    let mut router = router();
    let router_ip = ip6("2001:db8:1::1");
    let target = ip6("2001:db8:1::71");
    let wire_mac = mac(0x71);
    let queued = Ipv6Packet::serialize(router_ip, target, 59, 64, b"queued");
    router
        .pending_ipv6_transit_packets
        .insert(("eth0".to_string(), target), vec![queued]);

    let na = Icmpv6Packet::build_neighbor_advertisement(
        target, router_ip, target, wire_mac, false, true, true,
    );
    let na = without_ethernet_lla_option(na, target, router_ip);
    let frame = ipv6_frame(wire_mac, mac(0x10), target, router_ip, &na);
    let released = router.process_incoming_frame("lan1", &frame);

    assert!(released.is_empty());
    assert_eq!(router.ndp_tables["eth0"].lookup(&target), None);
    assert_eq!(
        router
            .pending_ipv6_transit_packets
            .get(&("eth0".to_string(), target))
            .map(Vec::len),
        Some(1)
    );
}

#[test]
fn router_link_local_source_accessor_uses_ndp_option_not_interface_mac() {
    let mut router = router();
    let wire_mac = mac(0x81);
    let advertised_mac = mac(0x82);
    let source = link_local_address(advertised_mac);
    let target = ip6("2001:db8:1::1");
    let dst = target.solicited_node_multicast();
    let ns = Icmpv6Packet::build_neighbor_solicitation(source, dst, target, advertised_mac);
    let frame = ipv6_frame(wire_mac, ipv6_multicast_mac(dst).unwrap(), source, dst, &ns);

    assert_eq!(router.process_incoming_frame("lan1", &frame).len(), 1);
    assert_eq!(
        router.ndp_tables["eth0"].lookup(&source),
        Some(advertised_mac)
    );
}

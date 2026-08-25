use std::str::FromStr;

use toy_tcpip::ethernet::{ETHERTYPE_IPV6, EthernetFrame, MacAddress};
use toy_tcpip::icmpv6::{ICMPV6_TYPE_NEIGHBOR_SOLICIT, Icmpv6Packet, ipv6_multicast_mac};
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::{Ipv6Address, Ipv6Packet, NEXT_HEADER_ICMPV6};
use toy_tcpip::lab::LabRouter;
use toy_tcpip::stack::{NetStack, NetStackConfig};

fn ip6(text: &str) -> Ipv6Address {
    Ipv6Address::from_str(text).unwrap()
}

fn mac(a: u8, b: u8) -> MacAddress {
    MacAddress([0x02, 0, 0, 0, a, b])
}

fn host_stack(address: Ipv6Address, gateway: Option<Ipv6Address>) -> NetStack {
    let mut stack = NetStack::new(NetStackConfig {
        mac: mac(1, 2),
        ip: Ipv4Address::new(192, 0, 2, 2),
        ipv6: None,
        subnet_mask: 24,
        gateway: None,
    });
    stack.configure_ipv6_interface(address, 64, gateway);
    stack
}

fn ns_frame(
    src: Ipv6Address,
    dst: Ipv6Address,
    target: Ipv6Address,
    src_mac: MacAddress,
    dst_mac: MacAddress,
    hop_limit: u8,
) -> Vec<u8> {
    let ns = Icmpv6Packet::build_neighbor_solicitation(src, dst, target, src_mac);
    let packet = Ipv6Packet::serialize(src, dst, NEXT_HEADER_ICMPV6, hop_limit, &ns);
    EthernetFrame::serialize(dst_mac, src_mac, ETHERTYPE_IPV6, &packet)
}

#[test]
fn host_rejects_offlink_ns_before_neighbor_cache_learning() {
    let host_ip = ip6("2001:db8:1::2");
    let attacker_ip = ip6("2001:db8:1::99");
    let attacker_mac = mac(9, 9);
    let dst = host_ip.solicited_node_multicast();
    let dst_mac = ipv6_multicast_mac(dst).unwrap();
    let mut stack = host_stack(host_ip, None);

    let invalid = ns_frame(attacker_ip, dst, host_ip, attacker_mac, dst_mac, 64);
    assert!(stack.process_frame(&invalid).is_empty());
    assert_eq!(stack.ndp_table.lookup(&attacker_ip), None);

    let valid = ns_frame(attacker_ip, dst, host_ip, attacker_mac, dst_mac, 255);
    let replies = stack.process_frame(&valid);
    assert_eq!(replies.len(), 1, "a valid NS must still receive an NA");
    assert_eq!(stack.ndp_table.lookup(&attacker_ip), Some(attacker_mac));
}

#[test]
fn host_rejects_multicast_solicited_na_without_releasing_pending_packet() {
    let host_ip = ip6("2001:db8:1::2");
    let gateway = ip6("fe80::abcd:1234");
    let remote = ip6("2001:db8:2::2");
    let gateway_mac = mac(4, 4);
    let mut stack = host_stack(host_ip, Some(gateway));

    let _ns = stack.ping6(remote, 0x600d, 1, b"queued").unwrap();
    assert_eq!(
        stack.pending_ndp_packets.get(&gateway).map(Vec::len),
        Some(1)
    );

    let multicast_dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let invalid_na = Icmpv6Packet::build_neighbor_advertisement(
        gateway,
        multicast_dst,
        gateway,
        gateway_mac,
        false,
        true,
        true,
    );
    let invalid_ip =
        Ipv6Packet::serialize(gateway, multicast_dst, NEXT_HEADER_ICMPV6, 255, &invalid_na);
    let invalid_frame = EthernetFrame::serialize(
        ipv6_multicast_mac(multicast_dst).unwrap(),
        gateway_mac,
        ETHERTYPE_IPV6,
        &invalid_ip,
    );
    assert!(stack.process_frame(&invalid_frame).is_empty());
    assert_eq!(stack.ndp_table.lookup(&gateway), None);
    assert_eq!(
        stack.pending_ndp_packets.get(&gateway).map(Vec::len),
        Some(1)
    );

    let valid_na = Icmpv6Packet::build_neighbor_advertisement(
        gateway,
        host_ip,
        gateway,
        gateway_mac,
        false,
        true,
        true,
    );
    let valid_ip = Ipv6Packet::serialize(gateway, host_ip, NEXT_HEADER_ICMPV6, 255, &valid_na);
    let valid_frame =
        EthernetFrame::serialize(stack.config.mac, gateway_mac, ETHERTYPE_IPV6, &valid_ip);
    let released = stack.process_frame(&valid_frame);
    assert_eq!(released.len(), 1, "valid NA must release the queued packet");
    assert_eq!(stack.ndp_table.lookup(&gateway), Some(gateway_mac));
    assert!(!stack.pending_ndp_packets.contains_key(&gateway));
}

#[test]
fn router_rejects_invalid_ndp_before_learning_sender() {
    let router_ip = ip6("2001:db8:1::1");
    let neighbor_ip = ip6("2001:db8:1::2");
    let router_mac = mac(1, 1);
    let neighbor_mac = mac(2, 2);
    let mut router = LabRouter::new("r1");
    router.add_interface("eth0", router_mac, Ipv4Address::new(10, 0, 0, 1), 24, "lan");
    assert!(router.set_interface_ipv6("eth0", router_ip, 64));

    let ns_dst = router_ip.solicited_node_multicast();
    let invalid_ns = ns_frame(
        neighbor_ip,
        ns_dst,
        router_ip,
        neighbor_mac,
        ipv6_multicast_mac(ns_dst).unwrap(),
        64,
    );
    assert!(router.process_incoming_frame("lan", &invalid_ns).is_empty());
    assert_eq!(
        router.ndp_tables.get("eth0").unwrap().lookup(&neighbor_ip),
        None
    );

    let valid_ns = ns_frame(
        neighbor_ip,
        ns_dst,
        router_ip,
        neighbor_mac,
        ipv6_multicast_mac(ns_dst).unwrap(),
        255,
    );
    assert_eq!(router.process_incoming_frame("lan", &valid_ns).len(), 1);
    assert_eq!(
        router.ndp_tables.get("eth0").unwrap().lookup(&neighbor_ip),
        Some(neighbor_mac)
    );
}

#[test]
fn router_rejects_offlink_na_before_neighbor_cache_learning() {
    let router_ip = ip6("2001:db8:1::1");
    let neighbor_ip = ip6("2001:db8:1::2");
    let router_mac = mac(1, 1);
    let neighbor_mac = mac(2, 2);
    let mut router = LabRouter::new("r1");
    router.add_interface("eth0", router_mac, Ipv4Address::new(10, 0, 0, 1), 24, "lan");
    assert!(router.set_interface_ipv6("eth0", router_ip, 64));

    let na = Icmpv6Packet::build_neighbor_advertisement(
        neighbor_ip,
        router_ip,
        neighbor_ip,
        neighbor_mac,
        false,
        true,
        true,
    );
    let invalid_ip = Ipv6Packet::serialize(neighbor_ip, router_ip, NEXT_HEADER_ICMPV6, 64, &na);
    let invalid_frame =
        EthernetFrame::serialize(router_mac, neighbor_mac, ETHERTYPE_IPV6, &invalid_ip);
    assert!(
        router
            .process_incoming_frame("lan", &invalid_frame)
            .is_empty()
    );
    assert_eq!(
        router.ndp_tables.get("eth0").unwrap().lookup(&neighbor_ip),
        None
    );

    let valid_ip = Ipv6Packet::serialize(neighbor_ip, router_ip, NEXT_HEADER_ICMPV6, 255, &na);
    let valid_frame = EthernetFrame::serialize(router_mac, neighbor_mac, ETHERTYPE_IPV6, &valid_ip);
    assert!(
        router
            .process_incoming_frame("lan", &valid_frame)
            .is_empty()
    );
    // A wire-valid NA still cannot create a Neighbor Cache entry out of thin air.
    // RFC 4861 section 7.2.5 discards it when no cache entry / INCOMPLETE
    // resolution exists; LabRouter NUD now mirrors NetStack here.
    assert_eq!(
        router.ndp_tables.get("eth0").unwrap().lookup(&neighbor_ip),
        None
    );
}

#[test]
fn dad_ns_with_source_lla_and_zero_length_ndp_option_are_rejected() {
    let target = ip6("2001:db8:1::1234");
    let dst = target.solicited_node_multicast();
    let sender_mac = mac(8, 8);

    // The normal NS builder includes SLLA, which is forbidden when source is ::.
    let dad_with_slla = Icmpv6Packet::build_neighbor_solicitation(
        Ipv6Address::UNSPECIFIED,
        dst,
        target,
        sender_mac,
    );
    let parsed = Icmpv6Packet::parse(Ipv6Address::UNSPECIFIED, dst, &dad_with_slla, true).unwrap();
    assert_eq!(parsed.msg_type, ICMPV6_TYPE_NEIGHBOR_SOLICIT);
    assert_eq!(
        parsed.validated_neighbor_solicitation_target(Ipv6Address::UNSPECIFIED, dst, 255,),
        None
    );

    // Option length zero is invalid and must not enter an endless option walk.
    let mut malformed =
        Icmpv6Packet::build_neighbor_solicitation(ip6("2001:db8:1::99"), dst, target, sender_mac);
    malformed[25] = 0; // SLLA option length byte: ICMP hdr 4 + NS fixed body 20 + 1.
    let packet = Icmpv6Packet {
        msg_type: malformed[0],
        code: malformed[1],
        checksum: 0,
        payload: &malformed[4..],
    };
    assert_eq!(
        packet.validated_neighbor_solicitation_target(ip6("2001:db8:1::99"), dst, 255,),
        None
    );
}

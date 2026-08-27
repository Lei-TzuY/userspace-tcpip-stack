use std::str::FromStr;

use toy_tcpip::ethernet::{ETHERTYPE_IPV6, EthernetFrame, MacAddress};
use toy_tcpip::icmpv6::{
    ICMPV6_TYPE_PACKET_TOO_BIG, ICMPV6_TYPE_TIME_EXCEEDED, Icmpv6Packet, ipv6_multicast_mac,
};
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::{
    Ipv6Address, Ipv6Packet, NEXT_HEADER_DEST_OPTS, NEXT_HEADER_FRAGMENT, NEXT_HEADER_HOP_BY_HOP,
    NEXT_HEADER_ICMPV6,
};
use toy_tcpip::lab::LabRouter;

fn ip6(text: &str) -> Ipv6Address {
    Ipv6Address::from_str(text).unwrap()
}

fn mac(last: u8) -> MacAddress {
    MacAddress([0x02, 0, 0, 0, 0, last])
}

fn make_router() -> LabRouter {
    let mut router = LabRouter::new("r1");
    router.add_interface(
        "eth0",
        mac(0x10),
        Ipv4Address::new(192, 0, 2, 1),
        24,
        "lan1",
    );
    router.add_interface(
        "eth1",
        mac(0x20),
        Ipv4Address::new(198, 51, 100, 1),
        24,
        "lan2",
    );
    assert!(router.set_interface_ipv6("eth0", ip6("2001:db8:1::1"), 64));
    assert!(router.set_interface_ipv6("eth1", ip6("2001:db8:2::1"), 64));
    assert!(router.set_interface_ipv6_mtu("eth1", 1280));
    router
}

fn frame(
    src: Ipv6Address,
    dst: Ipv6Address,
    next_header: u8,
    hop_limit: u8,
    payload: &[u8],
    frame_dst: MacAddress,
) -> Vec<u8> {
    let packet = Ipv6Packet::serialize(src, dst, next_header, hop_limit, payload);
    EthernetFrame::serialize(frame_dst, mac(0x11), ETHERTYPE_IPV6, &packet)
}

#[test]
fn ordinary_unicast_hop_limit_expiry_still_returns_time_exceeded() {
    let mut router = make_router();
    let source = ip6("2001:db8:1::2");
    let destination = ip6("2001:db8:2::2");
    let raw = frame(source, destination, 17, 1, b"ttl", mac(0x10));

    let out = router.process_incoming_frame("lan1", &raw);
    assert_eq!(out.len(), 1);
    let eth = EthernetFrame::parse(&out[0].1).unwrap();
    let ip = Ipv6Packet::parse(eth.payload).unwrap();
    assert_eq!(ip.header.dst_ip, source);
    let icmp = Icmpv6Packet::parse(ip.header.src_ip, ip.header.dst_ip, ip.payload, true).unwrap();
    assert_eq!(icmp.msg_type, ICMPV6_TYPE_TIME_EXCEEDED);
}

#[test]
fn time_exceeded_is_not_sent_in_response_to_an_icmpv6_error() {
    let mut router = make_router();
    let source = ip6("2001:db8:1::2");
    let destination = ip6("2001:db8:2::2");
    let inner = Ipv6Packet::serialize(destination, source, 17, 64, b"quoted");
    let error = Icmpv6Packet::build_destination_unreachable(source, destination, 0, &inner);
    let raw = frame(
        source,
        destination,
        NEXT_HEADER_ICMPV6,
        1,
        &error,
        mac(0x10),
    );

    assert!(router.process_incoming_frame("lan1", &raw).is_empty());
}

#[test]
fn time_exceeded_is_suppressed_for_non_unique_ipv6_sources() {
    let destination = ip6("2001:db8:2::2");
    for source in [Ipv6Address::UNSPECIFIED, ip6("ff02::1234")] {
        let mut router = make_router();
        let raw = frame(source, destination, 17, 1, b"ttl", mac(0x10));
        assert!(
            router.process_incoming_frame("lan1", &raw).is_empty(),
            "source {source} must not receive an ICMPv6 error"
        );
    }
}

#[test]
fn time_exceeded_is_suppressed_for_ipv6_and_link_layer_multicast() {
    let source = ip6("2001:db8:1::2");

    let multicast_destination = ip6("ff02::1234");
    let mut router = make_router();
    let raw = frame(
        source,
        multicast_destination,
        17,
        1,
        b"ttl",
        ipv6_multicast_mac(multicast_destination).unwrap(),
    );
    assert!(router.process_incoming_frame("lan1", &raw).is_empty());

    let unicast_destination = ip6("2001:db8:2::2");
    let mut router = make_router();
    let raw = frame(
        source,
        unicast_destination,
        17,
        1,
        b"ttl",
        MacAddress([0x33, 0x33, 0, 0, 0, 1]),
    );
    assert!(router.process_incoming_frame("lan1", &raw).is_empty());
}

#[test]
fn packet_too_big_suppresses_non_unique_source_but_keeps_multicast_exception() {
    let destination = ip6("2001:db8:2::2");
    let large = vec![0x5a; 1300];

    let mut router = make_router();
    let raw = frame(ip6("ff02::1234"), destination, 17, 64, &large, mac(0x10));
    assert!(
        router.process_incoming_frame("lan1", &raw).is_empty(),
        "PTB still cannot target a multicast source"
    );

    let source = ip6("2001:db8:1::2");
    let multicast_destination = ip6("ff05::1234");
    let mut router = make_router();
    router
        .ipv6_routing_table
        .add_route(ip6("ff00::"), 8, None, "eth1");
    let raw = frame(
        source,
        multicast_destination,
        17,
        64,
        &large,
        ipv6_multicast_mac(multicast_destination).unwrap(),
    );
    let out = router.process_incoming_frame("lan1", &raw);
    assert_eq!(out.len(), 1, "RFC 4443 explicitly permits multicast PTB");
    let eth = EthernetFrame::parse(&out[0].1).unwrap();
    let ip = Ipv6Packet::parse(eth.payload).unwrap();
    assert_eq!(ip.header.dst_ip, source);
    let icmp = Icmpv6Packet::parse(ip.header.src_ip, ip.header.dst_ip, ip.payload, true).unwrap();
    assert_eq!(icmp.msg_type, ICMPV6_TYPE_PACKET_TOO_BIG);
}

fn extension_header(next_header: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![next_header, 0, 0, 0, 0, 0, 0, 0];
    out.extend_from_slice(body);
    out
}

#[test]
fn time_exceeded_is_suppressed_for_icmpv6_error_behind_extension_headers() {
    let mut router = make_router();
    let source = ip6("2001:db8:1::2");
    let destination = ip6("2001:db8:2::2");
    let inner = Ipv6Packet::serialize(destination, source, 17, 64, b"quoted");
    let error = Icmpv6Packet::build_destination_unreachable(source, destination, 0, &inner);
    let destination_options = extension_header(NEXT_HEADER_ICMPV6, &error);
    let hop_by_hop = extension_header(NEXT_HEADER_DEST_OPTS, &destination_options);
    let raw = frame(
        source,
        destination,
        NEXT_HEADER_HOP_BY_HOP,
        1,
        &hop_by_hop,
        mac(0x10),
    );

    assert!(router.process_incoming_frame("lan1", &raw).is_empty());
}

#[test]
fn time_exceeded_is_suppressed_for_first_fragment_of_icmpv6_error() {
    let mut router = make_router();
    let source = ip6("2001:db8:1::2");
    let destination = ip6("2001:db8:2::2");
    let inner = Ipv6Packet::serialize(destination, source, 17, 64, b"quoted");
    let error = Icmpv6Packet::build_destination_unreachable(source, destination, 0, &inner);
    let mut fragment = vec![NEXT_HEADER_ICMPV6, 0, 0, 0, 0, 0, 0, 1];
    fragment.extend_from_slice(&error);
    let raw = frame(
        source,
        destination,
        NEXT_HEADER_FRAGMENT,
        1,
        &fragment,
        mac(0x10),
    );

    assert!(router.process_incoming_frame("lan1", &raw).is_empty());
}

#[test]
fn time_exceeded_fails_closed_for_non_initial_icmpv6_fragment() {
    let mut router = make_router();
    let source = ip6("2001:db8:1::2");
    let destination = ip6("2001:db8:2::2");
    // Fragment offset 1 means the ICMPv6 type byte is not present in this fragment.
    // The Fragment header still identifies ICMPv6 as the fragmentable protocol, so
    // RFC 4443 error-to-error safety requires conservative suppression.
    let fragment = [
        NEXT_HEADER_ICMPV6,
        0,
        0,
        8,
        0,
        0,
        0,
        1,
        0xaa,
        0xbb,
        0xcc,
        0xdd,
    ];
    let raw = frame(
        source,
        destination,
        NEXT_HEADER_FRAGMENT,
        1,
        &fragment,
        mac(0x10),
    );

    assert!(router.process_incoming_frame("lan1", &raw).is_empty());
}

#[test]
fn time_exceeded_still_works_for_udp_behind_extension_header() {
    let mut router = make_router();
    let source = ip6("2001:db8:1::2");
    let destination = ip6("2001:db8:2::2");
    let hop_by_hop = extension_header(17, b"udp-payload");
    let raw = frame(
        source,
        destination,
        NEXT_HEADER_HOP_BY_HOP,
        1,
        &hop_by_hop,
        mac(0x10),
    );

    let out = router.process_incoming_frame("lan1", &raw);
    assert_eq!(out.len(), 1);
    let eth = EthernetFrame::parse(&out[0].1).unwrap();
    let ip = Ipv6Packet::parse(eth.payload).unwrap();
    let icmp = Icmpv6Packet::parse(ip.header.src_ip, ip.header.dst_ip, ip.payload, true).unwrap();
    assert_eq!(icmp.msg_type, ICMPV6_TYPE_TIME_EXCEEDED);
}

use std::str::FromStr;

use toy_tcpip::ethernet::{ETHERTYPE_IPV6, EthernetFrame, MacAddress};
use toy_tcpip::icmpv6::{ICMPV6_TYPE_DEST_UNREACHABLE, Icmpv6Packet, ipv6_multicast_mac};
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::{Ipv6Address, Ipv6Packet, NEXT_HEADER_ICMPV6};
use toy_tcpip::lab::LabRouter;

fn ip6(text: &str) -> Ipv6Address {
    Ipv6Address::from_str(text).unwrap()
}

fn router_mac() -> MacAddress {
    MacAddress([0x02, 0, 0, 0, 0, 0x10])
}

fn host_mac() -> MacAddress {
    MacAddress([0x02, 0, 0, 0, 0, 0x11])
}

fn make_router() -> LabRouter {
    let mut router = LabRouter::new("r1");
    router.add_interface(
        "eth0",
        router_mac(),
        Ipv4Address::new(192, 0, 2, 1),
        24,
        "lan1",
    );
    assert!(router.set_interface_ipv6("eth0", ip6("2001:db8:1::1"), 64));
    router
}

fn frame(
    src: Ipv6Address,
    dst: Ipv6Address,
    next_header: u8,
    payload: &[u8],
    frame_dst: MacAddress,
) -> Vec<u8> {
    let packet = Ipv6Packet::serialize(src, dst, next_header, 64, payload);
    EthernetFrame::serialize(frame_dst, host_mac(), ETHERTYPE_IPV6, &packet)
}

#[test]
fn unicast_route_miss_returns_destination_unreachable_code_zero() {
    let mut router = make_router();
    let source = ip6("2001:db8:1::2");
    let destination = ip6("2001:db8:ffff::9");
    let raw = frame(source, destination, 17, b"no-route", router_mac());
    let invoking = EthernetFrame::parse(&raw).unwrap().payload.to_vec();

    let out = router.process_incoming_frame("lan1", &raw);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].0, "lan1");

    let eth = EthernetFrame::parse(&out[0].1).unwrap();
    assert_eq!(eth.src_mac, router_mac());
    assert_eq!(eth.dst_mac, host_mac());
    let ip = Ipv6Packet::parse(eth.payload).unwrap();
    assert_eq!(ip.header.src_ip, ip6("2001:db8:1::1"));
    assert_eq!(ip.header.dst_ip, source);
    assert_eq!(ip.header.next_header, NEXT_HEADER_ICMPV6);
    let icmp = Icmpv6Packet::parse(ip.header.src_ip, ip.header.dst_ip, ip.payload, true).unwrap();
    assert_eq!(icmp.msg_type, ICMPV6_TYPE_DEST_UNREACHABLE);
    assert_eq!(icmp.code, 0);
    assert_eq!(&icmp.payload[..4], &[0, 0, 0, 0]);
    assert_eq!(&icmp.payload[4..], invoking.as_slice());
}

#[test]
fn route_miss_does_not_answer_an_icmpv6_error_with_another_error() {
    let mut router = make_router();
    let source = ip6("2001:db8:1::2");
    let destination = ip6("2001:db8:ffff::9");
    let quoted = Ipv6Packet::serialize(destination, source, 17, 64, b"quoted");
    let error = Icmpv6Packet::build_destination_unreachable(source, destination, 0, &quoted);
    let raw = frame(
        source,
        destination,
        NEXT_HEADER_ICMPV6,
        &error,
        router_mac(),
    );

    assert!(router.process_incoming_frame("lan1", &raw).is_empty());
}

#[test]
fn route_miss_suppresses_multicast_destination_errors() {
    let mut router = make_router();
    let source = ip6("2001:db8:1::2");
    let destination = ip6("ff05::1234");
    let raw = frame(
        source,
        destination,
        17,
        b"multicast",
        ipv6_multicast_mac(destination).unwrap(),
    );

    assert!(router.process_incoming_frame("lan1", &raw).is_empty());
}

#[test]
fn route_miss_suppresses_non_unique_sources() {
    let destination = ip6("2001:db8:ffff::9");
    for source in [Ipv6Address::UNSPECIFIED, ip6("ff02::1234")] {
        let mut router = make_router();
        let raw = frame(source, destination, 17, b"bad-source", router_mac());
        assert!(
            router.process_incoming_frame("lan1", &raw).is_empty(),
            "source {source} must not receive an ICMPv6 error"
        );
    }
}

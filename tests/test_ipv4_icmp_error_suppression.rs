use toy_tcpip::checksum::compute_checksum;
use toy_tcpip::ethernet::{ETHERTYPE_IPV4, EthernetFrame, MacAddress};
use toy_tcpip::icmp::{ICMP_TYPE_DEST_UNREACHABLE, ICMP_TYPE_TIME_EXCEEDED, IcmpPacket, IcmpType};
use toy_tcpip::ipv4::{IP_PROTO_ICMP, IP_PROTO_UDP, Ipv4Address, Ipv4Packet};
use toy_tcpip::lab::LabRouter;

fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Address {
    Ipv4Address::new(a, b, c, d)
}

fn mac(last: u8) -> MacAddress {
    MacAddress([0x02, 0, 0, 0, 0, last])
}

fn make_router() -> LabRouter {
    let mut router = LabRouter::new("r1");
    router.add_interface("eth0", mac(0x10), ip(192, 0, 2, 1), 24, "lan1");
    router.add_interface("eth1", mac(0x20), ip(198, 51, 100, 1), 24, "lan2");
    router
}

fn frame(
    src: Ipv4Address,
    dst: Ipv4Address,
    protocol: u8,
    ttl: u8,
    payload: &[u8],
    frame_dst: MacAddress,
) -> Vec<u8> {
    let packet = Ipv4Packet::serialize(src, dst, protocol, 0x1234, ttl, payload);
    EthernetFrame::serialize(frame_dst, mac(0x11), ETHERTYPE_IPV4, &packet)
}

fn parse_icmp_output(raw: &[u8]) -> IcmpPacket<'_> {
    let eth = EthernetFrame::parse(raw).unwrap();
    let packet = Ipv4Packet::parse(eth.payload, true).unwrap();
    IcmpPacket::parse(packet.payload, true).unwrap()
}

#[test]
fn ordinary_unicast_ttl_expiry_still_returns_time_exceeded() {
    let mut router = make_router();
    let raw = frame(
        ip(192, 0, 2, 2),
        ip(198, 51, 100, 2),
        IP_PROTO_UDP,
        1,
        b"udp",
        mac(0x10),
    );

    let out = router.process_incoming_frame("lan1", &raw);
    assert_eq!(out.len(), 1);
    let icmp = parse_icmp_output(&out[0].1);
    assert_eq!(icmp.icmp_type, IcmpType::TimeExceeded);
    assert_eq!(icmp.icmp_type.to_u8(), ICMP_TYPE_TIME_EXCEEDED);
    assert_eq!(icmp.code, 0);
}

#[test]
fn no_route_returns_network_unreachable() {
    let mut router = make_router();
    let raw = frame(
        ip(192, 0, 2, 2),
        ip(203, 0, 113, 9),
        IP_PROTO_UDP,
        64,
        b"udp",
        mac(0x10),
    );

    let out = router.process_incoming_frame("lan1", &raw);
    assert_eq!(out.len(), 1);
    let icmp = parse_icmp_output(&out[0].1);
    assert_eq!(icmp.icmp_type, IcmpType::DestinationUnreachable);
    assert_eq!(icmp.icmp_type.to_u8(), ICMP_TYPE_DEST_UNREACHABLE);
    assert_eq!(icmp.code, 0);
}

#[test]
fn ttl_expiry_is_suppressed_for_icmp_error_input() {
    let mut router = make_router();
    let quoted = Ipv4Packet::serialize(
        ip(198, 51, 100, 2),
        ip(192, 0, 2, 2),
        IP_PROTO_UDP,
        7,
        64,
        b"quoted",
    );
    let invoking_error = IcmpPacket::build_destination_unreachable(0, 0, &quoted);
    let raw = frame(
        ip(192, 0, 2, 2),
        ip(198, 51, 100, 2),
        IP_PROTO_ICMP,
        1,
        &invoking_error,
        mac(0x10),
    );

    assert!(router.process_incoming_frame("lan1", &raw).is_empty());
}

#[test]
fn icmp_errors_are_suppressed_for_ip_and_link_layer_broadcast_or_multicast() {
    let source = ip(192, 0, 2, 2);
    let cases = [
        (ip(224, 0, 0, 9), mac(0x10)),
        (Ipv4Address::BROADCAST, MacAddress::BROADCAST),
        (ip(192, 0, 2, 255), MacAddress::BROADCAST),
        (ip(198, 51, 100, 2), MacAddress([0x01, 0, 0x5e, 0, 0, 1])),
    ];

    for (destination, frame_dst) in cases {
        let mut router = make_router();
        let raw = frame(source, destination, IP_PROTO_UDP, 1, b"udp", frame_dst);
        assert!(
            router.process_incoming_frame("lan1", &raw).is_empty(),
            "destination {destination} / L2 {frame_dst} must not provoke ICMP"
        );
    }
}

#[test]
fn icmp_errors_are_suppressed_for_invalid_sources() {
    for source in [
        ip(0, 1, 2, 3),
        ip(127, 0, 0, 1),
        ip(224, 0, 0, 1),
        ip(240, 0, 0, 1),
        Ipv4Address::BROADCAST,
    ] {
        let mut router = make_router();
        let raw = frame(
            source,
            ip(198, 51, 100, 2),
            IP_PROTO_UDP,
            1,
            b"udp",
            mac(0x10),
        );
        assert!(
            router.process_incoming_frame("lan1", &raw).is_empty(),
            "source {source} must not receive ICMP error"
        );
    }
}

#[test]
fn icmp_errors_are_suppressed_for_non_initial_fragments() {
    let packet = Ipv4Packet::serialize(
        ip(192, 0, 2, 2),
        ip(198, 51, 100, 2),
        IP_PROTO_UDP,
        0x1234,
        1,
        b"fragment",
    );
    let mut packet = packet;
    // Fragment offset = 1 (8-byte units), with no MF requirement for this regression.
    packet[6] = 0;
    packet[7] = 1;
    packet[10] = 0;
    packet[11] = 0;
    let checksum = compute_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    let raw = EthernetFrame::serialize(mac(0x10), mac(0x11), ETHERTYPE_IPV4, &packet);

    let mut router = make_router();
    assert!(router.process_incoming_frame("lan1", &raw).is_empty());
}

from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    file = Path(path)
    text = file.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one marker, found {count}")
    file.write_text(text.replace(old, new, 1))


replace_once(
    "src/lab.rs",
    "\nimpl LabRouter {\n",
    r'''

/// RFC 4443 section 2.4(e) suppression rules shared by router-generated
/// ICMPv6 errors. The simulator cannot identify anycast sources, but it can
/// reject the explicitly non-unique unspecified and multicast source forms.
///
/// Packet Too Big (and Parameter Problem Code 2, if added later) are the only
/// error classes allowed in response to IPv6/link-layer multicast traffic, so
/// callers opt into that exception explicitly.
fn should_send_icmpv6_error(
    invoking: &Ipv6Packet<'_>,
    link_destination: MacAddress,
    allow_multicast_exception: bool,
) -> bool {
    if invoking.header.src_ip.is_unspecified() || invoking.header.src_ip.is_multicast() {
        return false;
    }

    let invoking_is_icmpv6_error = invoking.header.next_header == NEXT_HEADER_ICMPV6
        && invoking
            .payload
            .first()
            .is_some_and(|msg_type| *msg_type < 128);
    if invoking_is_icmpv6_error {
        return false;
    }

    allow_multicast_exception
        || (!invoking.header.dst_ip.is_multicast() && link_destination.is_unicast())
}

impl LabRouter {
''',
)

replace_once(
    "src/lab.rs",
    r'''                if ip6_pkt.header.hop_limit <= 1 {
                    if let Some((src, _)) = ingress_iface.ipv6 {
                        let exceeded = Icmpv6Packet::build_time_exceeded(
                            src,
                            ip6_pkt.header.src_ip,
                            eth.payload,
                        );
                        let reply = Ipv6Packet::serialize(
                            src,
                            ip6_pkt.header.src_ip,
                            NEXT_HEADER_ICMPV6,
                            64,
                            &exceeded,
                        );
                        out_transmissions.push((
                            ingress_link.to_string(),
                            EthernetFrame::serialize(
                                eth.src_mac,
                                ingress_iface.mac,
                                ETHERTYPE_IPV6,
                                &reply,
                            ),
                        ));
                    }
                    return out_transmissions;
                }
''',
    r'''                if ip6_pkt.header.hop_limit <= 1 {
                    if should_send_icmpv6_error(&ip6_pkt, eth.dst_mac, false)
                        && let Some((src, _)) = ingress_iface.ipv6
                    {
                        let exceeded = Icmpv6Packet::build_time_exceeded(
                            src,
                            ip6_pkt.header.src_ip,
                            eth.payload,
                        );
                        let reply = Ipv6Packet::serialize(
                            src,
                            ip6_pkt.header.src_ip,
                            NEXT_HEADER_ICMPV6,
                            64,
                            &exceeded,
                        );
                        out_transmissions.push((
                            ingress_link.to_string(),
                            EthernetFrame::serialize(
                                eth.src_mac,
                                ingress_iface.mac,
                                ETHERTYPE_IPV6,
                                &reply,
                            ),
                        ));
                    }
                    return out_transmissions;
                }
''',
)

replace_once(
    "src/lab.rs",
    r'''                if eth.payload.len() > egress_mtu as usize {
                    let invoking_is_icmpv6_error = ip6_pkt.header.next_header == NEXT_HEADER_ICMPV6
                        && ip6_pkt
                            .payload
                            .first()
                            .is_some_and(|msg_type| *msg_type < 128);
                    if !ip6_pkt.header.src_ip.is_unspecified() && !invoking_is_icmpv6_error {
                        let ptb_src = ingress_iface
                            .ipv6
                            .map(|(address, _)| address)
                            .unwrap_or_else(|| link_local_address(ingress_iface.mac));
                        let ptb = Icmpv6Packet::build_packet_too_big(
                            ptb_src,
                            ip6_pkt.header.src_ip,
                            egress_mtu,
                            eth.payload,
                        );
                        let reply = Ipv6Packet::serialize(
                            ptb_src,
                            ip6_pkt.header.src_ip,
                            NEXT_HEADER_ICMPV6,
                            64,
                            &ptb,
                        );
                        out_transmissions.push((
                            ingress_link.to_string(),
                            EthernetFrame::serialize(
                                eth.src_mac,
                                ingress_iface.mac,
                                ETHERTYPE_IPV6,
                                &reply,
                            ),
                        ));
                    }
                    return out_transmissions;
                }
''',
    r'''                if eth.payload.len() > egress_mtu as usize {
                    // RFC 4443 permits Packet Too Big for IPv6/link-layer multicast,
                    // but all other generic suppression rules still apply.
                    if should_send_icmpv6_error(&ip6_pkt, eth.dst_mac, true) {
                        let ptb_src = ingress_iface
                            .ipv6
                            .map(|(address, _)| address)
                            .unwrap_or_else(|| link_local_address(ingress_iface.mac));
                        let ptb = Icmpv6Packet::build_packet_too_big(
                            ptb_src,
                            ip6_pkt.header.src_ip,
                            egress_mtu,
                            eth.payload,
                        );
                        let reply = Ipv6Packet::serialize(
                            ptb_src,
                            ip6_pkt.header.src_ip,
                            NEXT_HEADER_ICMPV6,
                            64,
                            &ptb,
                        );
                        out_transmissions.push((
                            ingress_link.to_string(),
                            EthernetFrame::serialize(
                                eth.src_mac,
                                ingress_iface.mac,
                                ETHERTYPE_IPV6,
                                &reply,
                            ),
                        ));
                    }
                    return out_transmissions;
                }
''',
)

Path("tests/test_ipv6_icmp_error_suppression.rs").write_text(r'''use std::str::FromStr;

use toy_tcpip::ethernet::{ETHERTYPE_IPV6, EthernetFrame, MacAddress};
use toy_tcpip::icmpv6::{
    ICMPV6_TYPE_PACKET_TOO_BIG, ICMPV6_TYPE_TIME_EXCEEDED, Icmpv6Packet, ipv6_multicast_mac,
};
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::{Ipv6Address, Ipv6Packet, NEXT_HEADER_ICMPV6};
use toy_tcpip::lab::LabRouter;

fn ip6(text: &str) -> Ipv6Address {
    Ipv6Address::from_str(text).unwrap()
}

fn mac(last: u8) -> MacAddress {
    MacAddress([0x02, 0, 0, 0, 0, last])
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
    let mut router = router();
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
    let mut router = router();
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
        let mut router = router();
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
    let mut router = router();
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
    let mut router = router();
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

    let mut router = router();
    let raw = frame(
        ip6("ff02::1234"),
        destination,
        17,
        64,
        &large,
        mac(0x10),
    );
    assert!(
        router.process_incoming_frame("lan1", &raw).is_empty(),
        "PTB still cannot target a multicast source"
    );

    let source = ip6("2001:db8:1::2");
    let multicast_destination = ip6("ff05::1234");
    let mut router = router();
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
''')

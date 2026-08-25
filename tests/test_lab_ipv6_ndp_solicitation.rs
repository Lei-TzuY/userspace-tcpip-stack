use std::str::FromStr;

use toy_tcpip::ethernet::{ETHERTYPE_IPV6, EthernetFrame, MacAddress};
use toy_tcpip::icmpv6::{ICMPV6_TYPE_NEIGHBOR_SOLICIT, Icmpv6Packet, ipv6_multicast_mac};
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::{Ipv6Address, Ipv6Packet, NEXT_HEADER_ICMPV6};
use toy_tcpip::lab::LabRouter;

fn ip6(text: &str) -> Ipv6Address {
    Ipv6Address::from_str(text).unwrap()
}

fn mac(a: u8, b: u8) -> MacAddress {
    MacAddress([0x02, 0, 0, 0, a, b])
}

#[test]
fn router_ndp_miss_uses_solicited_node_multicast_on_ipv6_and_ethernet() {
    let mut router = LabRouter::new("r1");
    let ingress_mac = mac(1, 0);
    let egress_mac = mac(1, 1);
    let sender_mac = mac(0x0a, 2);
    let ingress_ip = ip6("2001:db8:1::1");
    let egress_ip = ip6("2001:db8:2::1");
    let sender_ip = ip6("2001:db8:1::2");
    let next_hop = ip6("2001:db8:2::abcd:1234");

    router.add_interface(
        "eth0",
        ingress_mac,
        Ipv4Address::new(10, 1, 0, 1),
        24,
        "lan1",
    );
    router.add_interface(
        "eth1",
        egress_mac,
        Ipv4Address::new(10, 2, 0, 1),
        24,
        "lan2",
    );
    assert!(router.set_interface_ipv6("eth0", ingress_ip, 64));
    assert!(router.set_interface_ipv6("eth1", egress_ip, 64));

    let packet = Ipv6Packet::serialize(sender_ip, next_hop, 17, 64, b"cold-ndp");
    let frame = EthernetFrame::serialize(ingress_mac, sender_mac, ETHERTYPE_IPV6, &packet);
    let out = router.process_incoming_frame("lan1", &frame);

    assert_eq!(out.len(), 1, "cold NDP must emit exactly one NS");
    assert_eq!(out[0].0, "lan2");

    let solicited = next_hop.solicited_node_multicast();
    let expected_multicast_mac = ipv6_multicast_mac(solicited).unwrap();
    let eth = EthernetFrame::parse(&out[0].1).unwrap();
    assert_eq!(eth.src_mac, egress_mac);
    assert_eq!(eth.dst_mac, expected_multicast_mac);

    let ipv6 = Ipv6Packet::parse(eth.payload).unwrap();
    assert_eq!(ipv6.header.src_ip, egress_ip);
    assert_eq!(ipv6.header.dst_ip, solicited);
    assert_eq!(ipv6.header.next_header, NEXT_HEADER_ICMPV6);
    assert_eq!(ipv6.header.hop_limit, 255);

    let icmp =
        Icmpv6Packet::parse(ipv6.header.src_ip, ipv6.header.dst_ip, ipv6.payload, true).unwrap();
    assert_eq!(icmp.msg_type, ICMPV6_TYPE_NEIGHBOR_SOLICIT);
    assert_eq!(icmp.code, 0);
    assert!(icmp.payload.len() >= 28);

    let mut target = [0u8; 16];
    target.copy_from_slice(&icmp.payload[4..20]);
    assert_eq!(Ipv6Address(target), next_hop);
    assert_eq!(icmp.payload[20], 1, "Source LLA option type");
    assert_eq!(icmp.payload[21], 1, "Source LLA option length");
    assert_eq!(&icmp.payload[22..28], &egress_mac.0);

    assert_eq!(
        router
            .pending_ipv6_transit_packets
            .get(&("eth1".to_string(), next_hop))
            .map(Vec::len),
        Some(1),
        "the original packet must remain queued until the NA arrives"
    );
}

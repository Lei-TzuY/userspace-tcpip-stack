use std::str::FromStr;

use toy_tcpip::ethernet::{ETHERTYPE_IPV6, EthernetFrame, MacAddress};
use toy_tcpip::icmpv6::{ICMPV6_TYPE_NEIGHBOR_SOLICIT, Icmpv6Packet, ipv6_multicast_mac};
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::{Ipv6Address, Ipv6Packet, NEXT_HEADER_ICMPV6};
use toy_tcpip::stack::{NetStack, NetStackConfig};

fn ip6(text: &str) -> Ipv6Address {
    Ipv6Address::from_str(text).unwrap()
}

#[test]
fn host_ndp_miss_uses_solicited_node_multicast_on_ipv6_and_ethernet() {
    let host_mac = MacAddress([0x02, 0, 0, 0, 1, 2]);
    let host_ip = ip6("2001:db8:1::2");
    let gateway = ip6("fe80::abcd:1234");
    let destination = ip6("2001:db8:2::2");
    let mut stack = NetStack::new(NetStackConfig {
        mac: host_mac,
        ip: Ipv4Address::new(192, 0, 2, 2),
        ipv6: None,
        subnet_mask: 24,
        gateway: None,
    });
    stack.configure_ipv6_interface(host_ip, 64, Some(gateway));

    let frame = stack
        .ping6(destination, 0x600d, 7, b"host-cold-ndp")
        .expect("cold NDP must emit a Neighbor Solicitation");

    let solicited = gateway.solicited_node_multicast();
    let eth = EthernetFrame::parse(&frame).unwrap();
    assert_eq!(eth.ethertype, toy_tcpip::ethernet::EtherType::IPv6);
    assert_eq!(eth.src_mac, host_mac);
    assert_eq!(eth.dst_mac, ipv6_multicast_mac(solicited).unwrap());

    let ipv6 = Ipv6Packet::parse(eth.payload).unwrap();
    assert_eq!(ipv6.header.src_ip, host_ip);
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
    assert_eq!(Ipv6Address(target), gateway);
    assert_eq!(icmp.payload[20], 1, "Source LLA option type");
    assert_eq!(icmp.payload[21], 1, "Source LLA option length");
    assert_eq!(&icmp.payload[22..28], &host_mac.0);

    assert_eq!(
        stack.pending_ndp_packets.get(&gateway).map(Vec::len),
        Some(1),
        "the original IPv6 packet must stay queued until the NA arrives"
    );
}

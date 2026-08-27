use std::str::FromStr;

use toy_tcpip::ethernet::{ETHERTYPE_IPV6, EthernetFrame, MacAddress};
use toy_tcpip::icmpv6::{Icmpv6Packet, RouterAdvertisement, RouterPreference, ipv6_multicast_mac};
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::{
    Ipv6Address, Ipv6Packet, NEXT_HEADER_ICMPV6, compute_ipv6_transport_checksum,
};
use toy_tcpip::stack::{IPV6_ETHERNET_LINK_MTU, NetStack, NetStackConfig};

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

fn ra_bytes(current_hop_limit: u8, mtu: Option<u32>) -> Vec<u8> {
    let router = ip6("fe80::1");
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    Icmpv6Packet::build_router_advertisement_with_routes_and_mtu(
        router,
        dst,
        current_hop_limit,
        1800,
        RouterPreference::Medium,
        &[],
        &[],
        Some(mac(0x01)),
        mtu,
    )
}

fn ra_frame(current_hop_limit: u8, mtu: Option<u32>, outer_hop_limit: u8) -> Vec<u8> {
    let router = ip6("fe80::1");
    let router_mac = mac(0x01);
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let ra = ra_bytes(current_hop_limit, mtu);
    let packet = Ipv6Packet::serialize(router, dst, NEXT_HEADER_ICMPV6, outer_hop_limit, &ra);
    EthernetFrame::serialize(
        ipv6_multicast_mac(dst).unwrap(),
        router_mac,
        ETHERTYPE_IPV6,
        &packet,
    )
}

#[test]
fn mtu_option_builder_and_parser_round_trip() {
    let router = ip6("fe80::1");
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let raw = ra_bytes(64, Some(1400));
    let icmp = Icmpv6Packet::parse(router, dst, &raw, true).unwrap();
    let ra = RouterAdvertisement::parse(&icmp).unwrap();
    assert_eq!(ra.mtu, Some(1400));
}

#[test]
fn valid_ra_mtu_sets_link_mtu_and_enforces_exact_boundary() {
    let mut stack = host();
    assert_eq!(stack.ipv6_link_mtu(), IPV6_ETHERNET_LINK_MTU);
    assert!(
        stack
            .process_frame(&ra_frame(64, Some(1400), 255))
            .is_empty()
    );
    assert_eq!(stack.ipv6_link_mtu(), 1400);

    let peer = ip6("2001:db8:1::20");
    stack.ndp_table.insert(peer, mac(0x20));

    // IPv6 header (40) + ICMPv6 Echo header (8) + 1352 payload = exactly 1400.
    let exact = stack.ping6(peer, 1, 1, &vec![0x5a; 1352]).unwrap();
    let eth = EthernetFrame::parse(&exact).unwrap();
    assert_eq!(eth.payload.len(), 1400);

    // One byte larger is rejected at the source; IPv6 source fragmentation is
    // intentionally not modelled by this deterministic stack.
    assert!(stack.ping6(peer, 1, 2, &vec![0x5a; 1353]).is_none());
}

#[test]
fn ethernet_out_of_range_ra_mtu_values_are_ignored() {
    let mut stack = host();
    assert!(
        stack
            .process_frame(&ra_frame(64, Some(1400), 255))
            .is_empty()
    );
    assert_eq!(stack.ipv6_link_mtu(), 1400);

    assert!(
        stack
            .process_frame(&ra_frame(64, Some(1279), 255))
            .is_empty()
    );
    assert_eq!(stack.ipv6_link_mtu(), 1400);

    assert!(
        stack
            .process_frame(&ra_frame(64, Some(1501), 255))
            .is_empty()
    );
    assert_eq!(stack.ipv6_link_mtu(), 1400);
}

#[test]
fn absent_mtu_option_preserves_current_link_mtu() {
    let mut stack = host();
    assert!(
        stack
            .process_frame(&ra_frame(64, Some(1380), 255))
            .is_empty()
    );
    assert_eq!(stack.ipv6_link_mtu(), 1380);

    assert!(stack.process_frame(&ra_frame(64, None, 255)).is_empty());
    assert_eq!(stack.ipv6_link_mtu(), 1380);
}

#[test]
fn invalid_ra_cannot_change_link_mtu() {
    let mut stack = host();
    assert!(
        stack
            .process_frame(&ra_frame(64, Some(1300), 64))
            .is_empty()
    );
    assert_eq!(stack.ipv6_link_mtu(), IPV6_ETHERNET_LINK_MTU);
}

#[test]
fn malformed_mtu_option_is_ignored_without_discarding_other_ra_parameters() {
    let router = ip6("fe80::1");
    let router_mac = mac(0x01);
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let mut ra = ra_bytes(37, None);

    // Type 5 with a non-zero but wrong Length=2. RFC 4861 RA validation rejects
    // zero-length options; this malformed parameter itself is ignored.
    ra.extend_from_slice(&[5, 2]);
    ra.extend_from_slice(&[0; 14]);
    ra[2..4].copy_from_slice(&[0, 0]);
    let checksum = compute_ipv6_transport_checksum(router, dst, NEXT_HEADER_ICMPV6, &ra);
    ra[2..4].copy_from_slice(&checksum.to_be_bytes());

    let packet = Ipv6Packet::serialize(router, dst, NEXT_HEADER_ICMPV6, 255, &ra);
    let frame = EthernetFrame::serialize(
        ipv6_multicast_mac(dst).unwrap(),
        router_mac,
        ETHERTYPE_IPV6,
        &packet,
    );
    let mut stack = host();
    assert!(stack.process_frame(&frame).is_empty());
    assert_eq!(stack.ipv6_link_mtu(), IPV6_ETHERNET_LINK_MTU);
    assert_eq!(stack.ipv6_default_hop_limit(), 37);
}

#[test]
fn lowering_link_mtu_discards_oversized_packets_waiting_on_ndp() {
    let mut stack = host();
    let peer = ip6("2001:db8:1::30");

    // 1450-byte packet is legal under the Ethernet default but queues while NDP
    // resolves the peer.
    let ns = stack.ping6(peer, 7, 1, &vec![0x33; 1402]).unwrap();
    let ns_eth = EthernetFrame::parse(&ns).unwrap();
    assert_eq!(ns_eth.ethertype, toy_tcpip::ethernet::EtherType::IPv6);
    assert_eq!(stack.pending_ndp_packets.get(&peer).map(Vec::len), Some(1));

    assert!(
        stack
            .process_frame(&ra_frame(64, Some(1400), 255))
            .is_empty()
    );
    assert_eq!(stack.ipv6_link_mtu(), 1400);
    assert!(stack.pending_ndp_packets.get(&peer).is_none());
}

#[test]
fn clearing_ipv6_interface_restores_ethernet_link_mtu() {
    let mut stack = host();
    assert!(
        stack
            .process_frame(&ra_frame(64, Some(1280), 255))
            .is_empty()
    );
    assert_eq!(stack.ipv6_link_mtu(), 1280);

    stack.clear_ipv6_interface();
    assert_eq!(stack.ipv6_link_mtu(), IPV6_ETHERNET_LINK_MTU);
}

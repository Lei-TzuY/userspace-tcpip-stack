use std::str::FromStr;

use toy_tcpip::ethernet::{ETHERTYPE_IPV6, EthernetFrame, MacAddress};
use toy_tcpip::icmpv6::{ICMPV6_TYPE_PACKET_TOO_BIG, Icmpv6Packet};
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

fn host(address: Ipv6Address, gateway: Ipv6Address, host_mac: MacAddress) -> NetStack {
    let mut host = NetStack::new(NetStackConfig {
        mac: host_mac,
        ip: Ipv4Address::new(192, 0, 2, 2),
        ipv6: None,
        subnet_mask: 24,
        gateway: None,
    });
    host.configure_ipv6_interface(address, 64, Some(gateway));
    host
}

#[test]
fn router_ptb_teaches_host_path_mtu_and_suppresses_later_oversized_packets() {
    let host_ip = ip6("2001:db8:1::2");
    let ingress_ip = ip6("2001:db8:1::1");
    let egress_ip = ip6("2001:db8:2::1");
    let remote_ip = ip6("2001:db8:2::2");
    let host_mac = mac(0x10, 2);
    let ingress_mac = mac(0x20, 1);
    let egress_mac = mac(0x20, 2);

    let mut host = host(host_ip, ingress_ip, host_mac);
    host.ndp_table.insert(ingress_ip, ingress_mac);

    let mut router = LabRouter::new("r1");
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
    assert!(!router.set_interface_ipv6_mtu("eth1", 1279));
    assert!(router.set_interface_ipv6_mtu("eth1", 1280));
    assert_eq!(router.interface_ipv6_mtu("eth1"), Some(1280));

    let large_payload = vec![0x5a; 1300];
    let first = host
        .ping6(remote_ip, 0x600d, 1, &large_payload)
        .expect("no PMTU is known yet, so the source sends the packet");
    let first_eth = EthernetFrame::parse(&first).unwrap();
    assert_eq!(first_eth.dst_mac, ingress_mac);
    let first_ip = Ipv6Packet::parse(first_eth.payload).unwrap();
    assert!(first_ip.header.payload_length as usize + 40 > 1280);

    let replies = router.process_incoming_frame("lan1", &first);
    assert_eq!(
        replies.len(),
        1,
        "oversized transit packet must produce one PTB"
    );
    assert_eq!(replies[0].0, "lan1", "PTB travels back toward the sender");
    assert!(router.pending_ipv6_transit_packets.is_empty());

    let ptb_eth = EthernetFrame::parse(&replies[0].1).unwrap();
    assert_eq!(ptb_eth.src_mac, ingress_mac);
    assert_eq!(ptb_eth.dst_mac, host_mac);
    let ptb_ip = Ipv6Packet::parse(ptb_eth.payload).unwrap();
    assert_eq!(ptb_ip.header.src_ip, ingress_ip);
    assert_eq!(ptb_ip.header.dst_ip, host_ip);
    assert_eq!(ptb_ip.header.next_header, NEXT_HEADER_ICMPV6);
    let ptb = Icmpv6Packet::parse(
        ptb_ip.header.src_ip,
        ptb_ip.header.dst_ip,
        ptb_ip.payload,
        true,
    )
    .unwrap();
    assert_eq!(ptb.msg_type, ICMPV6_TYPE_PACKET_TOO_BIG);
    assert_eq!(ptb.code, 0);
    assert!(ptb.payload.len() >= 44);
    assert_eq!(
        u32::from_be_bytes(ptb.payload[0..4].try_into().unwrap()),
        1280
    );
    assert_eq!(
        ptb.payload[4] >> 4,
        6,
        "PTB must quote the invoking IPv6 header"
    );
    assert_eq!(
        ptb.payload[11], 64,
        "quoted Hop Limit is the unforwarded original"
    );
    let mut quoted_dst = [0u8; 16];
    quoted_dst.copy_from_slice(&ptb.payload[28..44]);
    assert_eq!(Ipv6Address(quoted_dst), remote_ip);

    assert!(host.process_frame(&replies[0].1).is_empty());
    assert_eq!(host.ipv6_path_mtu(remote_ip), Some(1280));

    assert!(
        host.ping6(remote_ip, 0x600d, 2, &large_payload).is_none(),
        "a learned PMTU must suppress a later oversized source packet"
    );
    assert!(host.pending_ndp_packets.is_empty());

    let small_payload = vec![0x33; 1100];
    assert!(
        host.ping6(remote_ip, 0x600d, 3, &small_payload).is_some(),
        "packets below the PMTU remain sendable"
    );
}

#[test]
fn host_ignores_ptb_that_quotes_another_source_and_never_raises_a_learned_pmtu() {
    let host_ip = ip6("2001:db8:1::2");
    let gateway = ip6("2001:db8:1::1");
    let remote = ip6("2001:db8:9::9");
    let host_mac = mac(1, 2);
    let router_mac = mac(2, 1);
    let mut host = host(host_ip, gateway, host_mac);

    let other_src = ip6("2001:db8:1::99");
    let quoted_other = Ipv6Packet::serialize(other_src, remote, 17, 64, b"not-ours");
    let bogus = Icmpv6Packet::build_packet_too_big(gateway, host_ip, 1280, &quoted_other);
    let bogus_ip = Ipv6Packet::serialize(gateway, host_ip, NEXT_HEADER_ICMPV6, 64, &bogus);
    let bogus_frame = EthernetFrame::serialize(host_mac, router_mac, ETHERTYPE_IPV6, &bogus_ip);
    host.process_frame(&bogus_frame);
    assert_eq!(host.ipv6_path_mtu(remote), None);

    let quoted_ours = Ipv6Packet::serialize(host_ip, remote, 17, 64, b"ours");
    let low = Icmpv6Packet::build_packet_too_big(gateway, host_ip, 1280, &quoted_ours);
    let low_ip = Ipv6Packet::serialize(gateway, host_ip, NEXT_HEADER_ICMPV6, 64, &low);
    host.process_frame(&EthernetFrame::serialize(
        host_mac,
        router_mac,
        ETHERTYPE_IPV6,
        &low_ip,
    ));
    assert_eq!(host.ipv6_path_mtu(remote), Some(1280));

    let higher = Icmpv6Packet::build_packet_too_big(gateway, host_ip, 1450, &quoted_ours);
    let higher_ip = Ipv6Packet::serialize(gateway, host_ip, NEXT_HEADER_ICMPV6, 64, &higher);
    host.process_frame(&EthernetFrame::serialize(
        host_mac,
        router_mac,
        ETHERTYPE_IPV6,
        &higher_ip,
    ));
    assert_eq!(host.ipv6_path_mtu(remote), Some(1280));

    host.clear_ipv6_path_mtu(remote);
    assert_eq!(host.ipv6_path_mtu(remote), None);
}

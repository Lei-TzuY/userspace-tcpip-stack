use std::str::FromStr;

use toy_tcpip::ethernet::{ETHERTYPE_IPV6, EthernetFrame, MacAddress};
use toy_tcpip::icmpv6::{
    ICMPV6_TYPE_NEIGHBOR_SOLICIT, Icmpv6Packet, NDP_DELAY_FIRST_PROBE_TIME_MS,
    NDP_RETRANS_TIMER_MS, NeighborState, ipv6_multicast_mac,
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
    let mut r = LabRouter::new("r1");
    r.add_interface(
        "eth0",
        mac(0x10),
        Ipv4Address::new(192, 0, 2, 1),
        24,
        "lan1",
    );
    r.add_interface(
        "eth1",
        mac(0x20),
        Ipv4Address::new(198, 51, 100, 1),
        24,
        "lan2",
    );
    assert!(r.set_interface_ipv6("eth0", ip6("2001:db8:1::1"), 64));
    assert!(r.set_interface_ipv6("eth1", ip6("2001:db8:2::1"), 64));
    r
}

fn transit_frame(src: Ipv6Address, dst: Ipv6Address, src_mac: MacAddress) -> Vec<u8> {
    let echo = Icmpv6Packet::build_echo_request(src, dst, 0x4861, 1, b"router-nud");
    let packet = Ipv6Packet::serialize(src, dst, NEXT_HEADER_ICMPV6, 64, &echo);
    EthernetFrame::serialize(mac(0x10), src_mac, ETHERTYPE_IPV6, &packet)
}

fn na_frame(
    src: Ipv6Address,
    dst: Ipv6Address,
    target: Ipv6Address,
    src_mac: MacAddress,
    dst_mac: MacAddress,
    solicited: bool,
    override_flag: bool,
) -> Vec<u8> {
    let na = Icmpv6Packet::build_neighbor_advertisement(
        src,
        dst,
        target,
        src_mac,
        false,
        solicited,
        override_flag,
    );
    let packet = Ipv6Packet::serialize(src, dst, NEXT_HEADER_ICMPV6, 255, &na);
    EthernetFrame::serialize(dst_mac, src_mac, ETHERTYPE_IPV6, &packet)
}

#[test]
fn transit_first_use_drives_delay_probe_timeout_and_multicast_reresolution() {
    let mut r = router();
    let source = ip6("2001:db8:1::2");
    let destination = ip6("2001:db8:2::2");
    let source_mac = mac(0x11);
    let destination_mac = mac(0x22);
    r.ndp_tables
        .get_mut("eth1")
        .unwrap()
        .mark_stale(destination, destination_mac);

    let first = r.process_incoming_frame("lan1", &transit_frame(source, destination, source_mac));
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].0, "lan2");
    assert_eq!(
        EthernetFrame::parse(&first[0].1).unwrap().dst_mac,
        destination_mac
    );
    assert_eq!(
        r.ndp_tables["eth1"].state(&destination),
        Some(NeighborState::Delay)
    );

    for now in [
        NDP_DELAY_FIRST_PROBE_TIME_MS,
        NDP_DELAY_FIRST_PROBE_TIME_MS + NDP_RETRANS_TIMER_MS,
        NDP_DELAY_FIRST_PROBE_TIME_MS + 2 * NDP_RETRANS_TIMER_MS,
    ] {
        let probes = r.step_timers(now);
        assert_eq!(probes.len(), 1, "one unicast NUD probe is due at {now}");
        assert_eq!(probes[0].0, "lan2");
        let eth = EthernetFrame::parse(&probes[0].1).unwrap();
        assert_eq!(eth.dst_mac, destination_mac);
        let ipv6 = Ipv6Packet::parse(eth.payload).unwrap();
        assert_eq!(ipv6.header.src_ip, ip6("2001:db8:2::1"));
        assert_eq!(ipv6.header.dst_ip, destination);
        assert_eq!(ipv6.header.hop_limit, 255);
        let icmp = Icmpv6Packet::parse(ipv6.header.src_ip, ipv6.header.dst_ip, ipv6.payload, true)
            .unwrap();
        assert_eq!(icmp.msg_type, ICMPV6_TYPE_NEIGHBOR_SOLICIT);
        assert_eq!(
            r.ndp_tables["eth1"].state(&destination),
            Some(NeighborState::Probe)
        );
    }

    assert!(
        r.step_timers(NDP_DELAY_FIRST_PROBE_TIME_MS + 3 * NDP_RETRANS_TIMER_MS)
            .is_empty()
    );
    assert_eq!(r.ndp_tables["eth1"].lookup(&destination), None);

    let retry = r.process_incoming_frame("lan1", &transit_frame(source, destination, source_mac));
    assert_eq!(retry.len(), 1);
    assert_eq!(retry[0].0, "lan2");
    let eth = EthernetFrame::parse(&retry[0].1).unwrap();
    let solicited = destination.solicited_node_multicast();
    assert_eq!(eth.dst_mac, ipv6_multicast_mac(solicited).unwrap());
    let ipv6 = Ipv6Packet::parse(eth.payload).unwrap();
    assert_eq!(ipv6.header.dst_ip, solicited);
    assert_eq!(
        r.pending_ipv6_transit_packets
            .get(&("eth1".to_string(), destination))
            .map(Vec::len),
        Some(1)
    );
}

#[test]
fn unsolicited_na_without_cache_or_resolution_does_not_create_router_neighbor() {
    let mut r = router();
    let peer = ip6("2001:db8:2::99");
    let all_nodes = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let frame = na_frame(
        peer,
        all_nodes,
        peer,
        mac(0x99),
        ipv6_multicast_mac(all_nodes).unwrap(),
        false,
        true,
    );
    assert!(r.process_incoming_frame("lan2", &frame).is_empty());
    assert_eq!(r.ndp_tables["eth1"].lookup(&peer), None);
}

#[test]
fn solicited_na_resolves_pending_transit_and_confirms_reachable() {
    let mut r = router();
    let source = ip6("2001:db8:1::2");
    let destination = ip6("2001:db8:2::2");
    let source_mac = mac(0x11);
    let destination_mac = mac(0x22);

    let miss = r.process_incoming_frame("lan1", &transit_frame(source, destination, source_mac));
    assert_eq!(miss.len(), 1);
    assert_eq!(r.ndp_tables["eth1"].lookup(&destination), None);

    let na = na_frame(
        destination,
        ip6("2001:db8:2::1"),
        destination,
        destination_mac,
        mac(0x20),
        true,
        true,
    );
    let released = r.process_incoming_frame("lan2", &na);
    assert_eq!(
        released.len(),
        1,
        "the queued transit packet must be released"
    );
    assert_eq!(released[0].0, "lan2");
    assert_eq!(
        EthernetFrame::parse(&released[0].1).unwrap().dst_mac,
        destination_mac
    );
    assert_eq!(
        r.ndp_tables["eth1"].state(&destination),
        Some(NeighborState::Reachable)
    );
    assert!(
        !r.pending_ipv6_transit_packets
            .contains_key(&("eth1".to_string(), destination))
    );
}

#[test]
fn neighbor_solicitation_learning_is_dynamic_stale_not_static() {
    let mut r = router();
    let host = ip6("2001:db8:2::2");
    let host_mac = mac(0x22);
    let target = ip6("2001:db8:2::1");
    let dst = target.solicited_node_multicast();
    let ns = Icmpv6Packet::build_neighbor_solicitation(host, dst, target, host_mac);
    let packet = Ipv6Packet::serialize(host, dst, NEXT_HEADER_ICMPV6, 255, &ns);
    let frame = EthernetFrame::serialize(
        ipv6_multicast_mac(dst).unwrap(),
        host_mac,
        ETHERTYPE_IPV6,
        &packet,
    );

    let replies = r.process_incoming_frame("lan2", &frame);
    assert_eq!(replies.len(), 1);
    assert_eq!(r.ndp_tables["eth1"].lookup(&host), Some(host_mac));
    assert_eq!(
        r.ndp_tables["eth1"].state(&host),
        Some(NeighborState::Stale)
    );
}

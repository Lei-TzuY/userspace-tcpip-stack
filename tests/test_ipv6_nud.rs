use std::str::FromStr;

use toy_tcpip::ethernet::{ETHERTYPE_IPV6, EthernetFrame, MacAddress};
use toy_tcpip::icmpv6::{
    ICMPV6_TYPE_NEIGHBOR_SOLICIT, Icmpv6Packet, NDP_DELAY_FIRST_PROBE_TIME_MS,
    NDP_REACHABLE_TIME_MS, NDP_RETRANS_TIMER_MS, NdpTable, NeighborState, ipv6_multicast_mac,
};
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::{
    Ipv6Address, Ipv6Packet, NEXT_HEADER_ICMPV6, compute_ipv6_transport_checksum,
};
use toy_tcpip::stack::{NetStack, NetStackConfig};

fn ip6(text: &str) -> Ipv6Address {
    Ipv6Address::from_str(text).unwrap()
}

fn mac(last: u8) -> MacAddress {
    MacAddress([0x02, 0, 0, 0, 0, last])
}

fn host(address: Ipv6Address, host_mac: MacAddress) -> NetStack {
    let mut stack = NetStack::new(NetStackConfig {
        mac: host_mac,
        ip: Ipv4Address::new(192, 0, 2, 2),
        ipv6: None,
        subnet_mask: 24,
        gateway: None,
    });
    stack.configure_ipv6_interface(address, 64, None);
    stack
}

fn na_frame(
    src: Ipv6Address,
    dst: Ipv6Address,
    target: Ipv6Address,
    src_mac: MacAddress,
    dst_mac: MacAddress,
    solicited: bool,
) -> Vec<u8> {
    na_frame_with_override(src, dst, target, src_mac, dst_mac, solicited, true)
}

fn na_frame_with_override(
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

fn ra_frame_with_nud_timers(
    router_ip: Ipv6Address,
    router_mac: MacAddress,
    reachable_time_ms: u32,
    retrans_timer_ms: u32,
    hop_limit: u8,
) -> Vec<u8> {
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let mut ra =
        Icmpv6Packet::build_router_advertisement(router_ip, dst, 64, 1800, &[], Some(router_mac));
    ra[8..12].copy_from_slice(&reachable_time_ms.to_be_bytes());
    ra[12..16].copy_from_slice(&retrans_timer_ms.to_be_bytes());
    ra[2..4].copy_from_slice(&[0, 0]);
    let checksum = compute_ipv6_transport_checksum(router_ip, dst, NEXT_HEADER_ICMPV6, &ra);
    ra[2..4].copy_from_slice(&checksum.to_be_bytes());
    let packet = Ipv6Packet::serialize(router_ip, dst, NEXT_HEADER_ICMPV6, hop_limit, &ra);
    EthernetFrame::serialize(
        ipv6_multicast_mac(dst).unwrap(),
        router_mac,
        ETHERTYPE_IPV6,
        &packet,
    )
}

fn na_frame_with_tlla(
    src: Ipv6Address,
    dst: Ipv6Address,
    target: Ipv6Address,
    ethernet_src_mac: MacAddress,
    dst_mac: MacAddress,
    target_mac: Option<MacAddress>,
    solicited: bool,
    override_flag: bool,
) -> Vec<u8> {
    let mut na = Icmpv6Packet::build_neighbor_advertisement(
        src,
        dst,
        target,
        target_mac.unwrap_or(ethernet_src_mac),
        false,
        solicited,
        override_flag,
    );
    if target_mac.is_none() {
        na.truncate(24);
        na[2..4].copy_from_slice(&[0, 0]);
        let checksum = compute_ipv6_transport_checksum(src, dst, NEXT_HEADER_ICMPV6, &na);
        na[2..4].copy_from_slice(&checksum.to_be_bytes());
    }
    let packet = Ipv6Packet::serialize(src, dst, NEXT_HEADER_ICMPV6, 255, &na);
    EthernetFrame::serialize(dst_mac, ethernet_src_mac, ETHERTYPE_IPV6, &packet)
}

#[test]
fn valid_ra_updates_reachable_and_retrans_timer_for_future_nud_transitions() {
    let host_ip = ip6("2001:db8:100::1");
    let router_ip = ip6("fe80::100");
    let peer_ip = ip6("2001:db8:100::2");
    let host_mac = mac(0x10);
    let router_mac = mac(0x11);
    let peer_mac = mac(0x12);
    let mut stack = host(host_ip, host_mac);

    let ra = ra_frame_with_nud_timers(router_ip, router_mac, 2_000, 250, 255);
    assert!(stack.process_frame(&ra).is_empty());

    stack.ndp_table.confirm_reachable(peer_ip, peer_mac, 100);
    assert!(stack.ndp_table.step_nud(2_099).is_empty());
    assert_eq!(
        stack.ndp_table.state(&peer_ip),
        Some(NeighborState::Reachable)
    );
    assert!(stack.ndp_table.step_nud(2_100).is_empty());
    assert_eq!(stack.ndp_table.state(&peer_ip), Some(NeighborState::Stale));

    assert_eq!(
        stack.ndp_table.lookup_for_transmit(&peer_ip, 2_100),
        Some(peer_mac)
    );
    let first_probe_at = 2_100 + NDP_DELAY_FIRST_PROBE_TIME_MS;
    assert_eq!(
        stack.ndp_table.step_nud(first_probe_at),
        vec![(peer_ip, peer_mac)]
    );
    assert!(stack.ndp_table.step_nud(first_probe_at + 249).is_empty());
    assert_eq!(
        stack.ndp_table.step_nud(first_probe_at + 250),
        vec![(peer_ip, peer_mac)]
    );
}

#[test]
fn zero_ra_nud_timers_preserve_previously_advertised_values() {
    let host_ip = ip6("2001:db8:101::1");
    let router_ip = ip6("fe80::101");
    let peer_ip = ip6("2001:db8:101::2");
    let host_mac = mac(0x20);
    let router_mac = mac(0x21);
    let peer_mac = mac(0x22);
    let mut stack = host(host_ip, host_mac);

    let learned = ra_frame_with_nud_timers(router_ip, router_mac, 1_500, 300, 255);
    assert!(stack.process_frame(&learned).is_empty());
    let unspecified = ra_frame_with_nud_timers(router_ip, router_mac, 0, 0, 255);
    assert!(stack.process_frame(&unspecified).is_empty());

    stack.ndp_table.confirm_reachable(peer_ip, peer_mac, 0);
    assert!(stack.ndp_table.step_nud(1_499).is_empty());
    assert_eq!(
        stack.ndp_table.state(&peer_ip),
        Some(NeighborState::Reachable)
    );
    assert!(stack.ndp_table.step_nud(1_500).is_empty());
    assert_eq!(stack.ndp_table.state(&peer_ip), Some(NeighborState::Stale));

    assert_eq!(
        stack.ndp_table.lookup_for_transmit(&peer_ip, 1_500),
        Some(peer_mac)
    );
    let first_probe_at = 1_500 + NDP_DELAY_FIRST_PROBE_TIME_MS;
    assert_eq!(
        stack.ndp_table.step_nud(first_probe_at),
        vec![(peer_ip, peer_mac)]
    );
    assert!(stack.ndp_table.step_nud(first_probe_at + 299).is_empty());
    assert_eq!(
        stack.ndp_table.step_nud(first_probe_at + 300),
        vec![(peer_ip, peer_mac)]
    );
}

#[test]
fn invalid_ra_cannot_change_nud_timers() {
    let host_ip = ip6("2001:db8:102::1");
    let router_ip = ip6("fe80::102");
    let peer_ip = ip6("2001:db8:102::2");
    let host_mac = mac(0x30);
    let router_mac = mac(0x31);
    let peer_mac = mac(0x32);
    let mut stack = host(host_ip, host_mac);

    let invalid = ra_frame_with_nud_timers(router_ip, router_mac, 100, 100, 64);
    assert!(stack.process_frame(&invalid).is_empty());

    stack.ndp_table.confirm_reachable(peer_ip, peer_mac, 0);
    assert!(stack.ndp_table.step_nud(100).is_empty());
    assert_eq!(
        stack.ndp_table.state(&peer_ip),
        Some(NeighborState::Reachable)
    );
    assert!(stack.ndp_table.step_nud(NDP_REACHABLE_TIME_MS).is_empty());
    assert_eq!(stack.ndp_table.state(&peer_ip), Some(NeighborState::Stale));

    assert_eq!(
        stack
            .ndp_table
            .lookup_for_transmit(&peer_ip, NDP_REACHABLE_TIME_MS),
        Some(peer_mac)
    );
    let first_probe_at = NDP_REACHABLE_TIME_MS + NDP_DELAY_FIRST_PROBE_TIME_MS;
    assert_eq!(
        stack.ndp_table.step_nud(first_probe_at),
        vec![(peer_ip, peer_mac)]
    );
    assert!(stack.ndp_table.step_nud(first_probe_at + 100).is_empty());
    assert_eq!(
        stack
            .ndp_table
            .step_nud(first_probe_at + NDP_RETRANS_TIMER_MS),
        vec![(peer_ip, peer_mac)]
    );
}

#[test]
fn reachable_ages_to_stale_and_first_use_enters_delay() {
    let neighbor = ip6("2001:db8:1::2");
    let neighbor_mac = mac(2);
    let mut table = NdpTable::new();
    table.confirm_reachable(neighbor, neighbor_mac, 100);
    assert_eq!(table.state(&neighbor), Some(NeighborState::Reachable));
    assert!(table.step_nud(100 + NDP_REACHABLE_TIME_MS - 1).is_empty());
    assert!(table.step_nud(100 + NDP_REACHABLE_TIME_MS).is_empty());
    assert_eq!(table.state(&neighbor), Some(NeighborState::Stale));
    assert_eq!(
        table.lookup_for_transmit(&neighbor, 100 + NDP_REACHABLE_TIME_MS),
        Some(neighbor_mac)
    );
    assert_eq!(table.state(&neighbor), Some(NeighborState::Delay));
}

#[test]
fn delay_probes_three_times_then_removes_unreachable_neighbor() {
    let neighbor = ip6("2001:db8:2::2");
    let neighbor_mac = mac(3);
    let mut table = NdpTable::new();
    table.mark_stale(neighbor, neighbor_mac);
    assert_eq!(table.lookup_for_transmit(&neighbor, 0), Some(neighbor_mac));
    assert!(table.step_nud(NDP_DELAY_FIRST_PROBE_TIME_MS - 1).is_empty());
    for now in [
        NDP_DELAY_FIRST_PROBE_TIME_MS,
        NDP_DELAY_FIRST_PROBE_TIME_MS + NDP_RETRANS_TIMER_MS,
        NDP_DELAY_FIRST_PROBE_TIME_MS + 2 * NDP_RETRANS_TIMER_MS,
    ] {
        assert_eq!(table.step_nud(now), vec![(neighbor, neighbor_mac)]);
        assert_eq!(table.state(&neighbor), Some(NeighborState::Probe));
    }
    assert!(
        table
            .step_nud(NDP_DELAY_FIRST_PROBE_TIME_MS + 3 * NDP_RETRANS_TIMER_MS)
            .is_empty()
    );
    assert_eq!(table.lookup(&neighbor), None);
}

#[test]
fn netstack_emits_unicast_nud_probes_and_then_restarts_resolution() {
    let host_ip = ip6("2001:db8:3::1");
    let peer_ip = ip6("2001:db8:3::2");
    let host_mac = mac(0x31);
    let peer_mac = mac(0x32);
    let mut stack = host(host_ip, host_mac);
    stack.ndp_table.mark_stale(peer_ip, peer_mac);
    let data = stack.ping6(peer_ip, 0x600d, 1, b"first").unwrap();
    assert_eq!(EthernetFrame::parse(&data).unwrap().dst_mac, peer_mac);
    for now in [
        NDP_DELAY_FIRST_PROBE_TIME_MS,
        NDP_DELAY_FIRST_PROBE_TIME_MS + NDP_RETRANS_TIMER_MS,
        NDP_DELAY_FIRST_PROBE_TIME_MS + 2 * NDP_RETRANS_TIMER_MS,
    ] {
        let frames = stack.step_timers(now);
        assert_eq!(frames.len(), 1);
        let eth = EthernetFrame::parse(&frames[0]).unwrap();
        assert_eq!(eth.dst_mac, peer_mac);
        let ip = Ipv6Packet::parse(eth.payload).unwrap();
        assert_eq!(ip.header.dst_ip, peer_ip);
        assert_eq!(ip.header.hop_limit, 255);
        let icmp =
            Icmpv6Packet::parse(ip.header.src_ip, ip.header.dst_ip, ip.payload, true).unwrap();
        assert_eq!(icmp.msg_type, ICMPV6_TYPE_NEIGHBOR_SOLICIT);
    }
    assert!(
        stack
            .step_timers(NDP_DELAY_FIRST_PROBE_TIME_MS + 3 * NDP_RETRANS_TIMER_MS)
            .is_empty()
    );
    assert_eq!(stack.ndp_table.lookup(&peer_ip), None);
    let resolution = stack.ping6(peer_ip, 0x600d, 2, b"retry").unwrap();
    let eth = EthernetFrame::parse(&resolution).unwrap();
    let solicited = peer_ip.solicited_node_multicast();
    assert_eq!(eth.dst_mac, ipv6_multicast_mac(solicited).unwrap());
    let ip = Ipv6Packet::parse(eth.payload).unwrap();
    assert_eq!(ip.header.dst_ip, solicited);
    assert_eq!(
        stack.pending_ndp_packets.get(&peer_ip).map(Vec::len),
        Some(1)
    );
}

#[test]
fn solicited_na_confirms_reachability_and_cancels_probe_cycle() {
    let host_ip = ip6("2001:db8:4::1");
    let peer_ip = ip6("2001:db8:4::2");
    let host_mac = mac(0x41);
    let peer_mac = mac(0x42);
    let mut stack = host(host_ip, host_mac);
    stack.ndp_table.mark_stale(peer_ip, peer_mac);
    stack.ping6(peer_ip, 0x4861, 1, b"nud").unwrap();
    assert_eq!(stack.step_timers(NDP_DELAY_FIRST_PROBE_TIME_MS).len(), 1);
    let frame = na_frame(peer_ip, host_ip, peer_ip, peer_mac, host_mac, true);
    assert!(stack.process_frame(&frame).is_empty());
    assert_eq!(
        stack.ndp_table.state(&peer_ip),
        Some(NeighborState::Reachable)
    );
    assert!(
        stack
            .step_timers(NDP_DELAY_FIRST_PROBE_TIME_MS + NDP_RETRANS_TIMER_MS)
            .is_empty()
    );
}

#[test]
fn unsolicited_na_updates_changed_existing_mapping_to_stale() {
    let host_ip = ip6("2001:db8:5::1");
    let peer_ip = ip6("2001:db8:5::2");
    let host_mac = mac(0x51);
    let old_mac = mac(0x52);
    let new_mac = mac(0x53);
    let mut stack = host(host_ip, host_mac);
    stack.ndp_table.confirm_reachable(peer_ip, old_mac, 0);
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let frame = na_frame(
        peer_ip,
        dst,
        peer_ip,
        new_mac,
        ipv6_multicast_mac(dst).unwrap(),
        false,
    );
    assert!(stack.process_frame(&frame).is_empty());
    assert_eq!(stack.ndp_table.lookup(&peer_ip), Some(new_mac));
    assert_eq!(stack.ndp_table.state(&peer_ip), Some(NeighborState::Stale));
}

#[test]
fn override_clear_na_preserves_reachable_mapping_and_marks_it_stale() {
    let host_ip = ip6("2001:db8:5:1::1");
    let peer_ip = ip6("2001:db8:5:1::2");
    let host_mac = mac(0x54);
    let old_mac = mac(0x55);
    let advertised_mac = mac(0x56);
    let mut stack = host(host_ip, host_mac);
    stack.ndp_table.confirm_reachable(peer_ip, old_mac, 0);

    let frame = na_frame_with_override(
        peer_ip,
        host_ip,
        peer_ip,
        advertised_mac,
        host_mac,
        true,
        false,
    );
    assert!(stack.process_frame(&frame).is_empty());
    assert_eq!(stack.ndp_table.lookup(&peer_ip), Some(old_mac));
    assert_eq!(stack.ndp_table.state(&peer_ip), Some(NeighborState::Stale));
}

#[test]
fn override_clear_na_with_changed_mac_is_ignored_for_delay_entry() {
    let host_ip = ip6("2001:db8:5:2::1");
    let peer_ip = ip6("2001:db8:5:2::2");
    let host_mac = mac(0x57);
    let old_mac = mac(0x58);
    let advertised_mac = mac(0x59);
    let mut stack = host(host_ip, host_mac);
    stack.ndp_table.mark_stale(peer_ip, old_mac);
    assert_eq!(
        stack.ndp_table.lookup_for_transmit(&peer_ip, 0),
        Some(old_mac)
    );
    assert_eq!(stack.ndp_table.state(&peer_ip), Some(NeighborState::Delay));

    let frame = na_frame_with_override(
        peer_ip,
        host_ip,
        peer_ip,
        advertised_mac,
        host_mac,
        true,
        false,
    );
    assert!(stack.process_frame(&frame).is_empty());
    assert_eq!(stack.ndp_table.lookup(&peer_ip), Some(old_mac));
    assert_eq!(stack.ndp_table.state(&peer_ip), Some(NeighborState::Delay));
}

#[test]
fn override_clear_na_does_not_turn_static_mapping_into_dynamic_state() {
    let host_ip = ip6("2001:db8:5:3::1");
    let peer_ip = ip6("2001:db8:5:3::2");
    let host_mac = mac(0x5a);
    let old_mac = mac(0x5b);
    let advertised_mac = mac(0x5c);
    let mut stack = host(host_ip, host_mac);
    stack.ndp_table.insert(peer_ip, old_mac);

    let frame = na_frame_with_override(
        peer_ip,
        host_ip,
        peer_ip,
        advertised_mac,
        host_mac,
        true,
        false,
    );
    assert!(stack.process_frame(&frame).is_empty());
    assert_eq!(stack.ndp_table.lookup(&peer_ip), Some(old_mac));
    assert_eq!(
        stack.ndp_table.state(&peer_ip),
        Some(NeighborState::Reachable)
    );
    assert_eq!(
        stack.ndp_table.lookup_for_transmit(&peer_ip, 1),
        Some(old_mac)
    );
    assert_eq!(
        stack.ndp_table.state(&peer_ip),
        Some(NeighborState::Reachable)
    );
}

#[test]
fn unsolicited_na_without_cache_or_resolution_state_is_discarded() {
    let host_ip = ip6("2001:db8:6::1");
    let peer_ip = ip6("2001:db8:6::2");
    let host_mac = mac(0x61);
    let peer_mac = mac(0x62);
    let mut stack = host(host_ip, host_mac);
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let frame = na_frame(
        peer_ip,
        dst,
        peer_ip,
        peer_mac,
        ipv6_multicast_mac(dst).unwrap(),
        false,
    );
    assert!(stack.process_frame(&frame).is_empty());
    assert_eq!(stack.ndp_table.lookup(&peer_ip), None);
    assert_eq!(stack.ndp_table.state(&peer_ip), None);
}

#[test]
fn incomplete_resolution_requires_tlla_and_uses_advertised_mac() {
    let host_ip = ip6("2001:db8:7::1");
    let peer_ip = ip6("2001:db8:7::2");
    let host_mac = mac(0x71);
    let ethernet_src = mac(0x72);
    let advertised_mac = mac(0x73);
    let mut stack = host(host_ip, host_mac);

    let _resolution = stack.ping6(peer_ip, 0x7000, 1, b"queued").unwrap();
    assert_eq!(
        stack.pending_ndp_packets.get(&peer_ip).map(Vec::len),
        Some(1)
    );

    let no_tlla = na_frame_with_tlla(
        peer_ip,
        host_ip,
        peer_ip,
        ethernet_src,
        host_mac,
        None,
        true,
        true,
    );
    assert!(stack.process_frame(&no_tlla).is_empty());
    assert_eq!(stack.ndp_table.lookup(&peer_ip), None);
    assert_eq!(
        stack.pending_ndp_packets.get(&peer_ip).map(Vec::len),
        Some(1)
    );

    let with_tlla = na_frame_with_tlla(
        peer_ip,
        host_ip,
        peer_ip,
        ethernet_src,
        host_mac,
        Some(advertised_mac),
        true,
        true,
    );
    let released = stack.process_frame(&with_tlla);
    assert_eq!(released.len(), 1);
    assert_eq!(
        EthernetFrame::parse(&released[0]).unwrap().dst_mac,
        advertised_mac
    );
    assert_eq!(stack.ndp_table.lookup(&peer_ip), Some(advertised_mac));
    assert_eq!(
        stack.ndp_table.state(&peer_ip),
        Some(NeighborState::Reachable)
    );
    assert!(!stack.pending_ndp_packets.contains_key(&peer_ip));
}

#[test]
fn solicited_na_without_tlla_confirms_cached_mac_without_replacing_it() {
    let host_ip = ip6("2001:db8:8::1");
    let peer_ip = ip6("2001:db8:8::2");
    let host_mac = mac(0x81);
    let cached_mac = mac(0x82);
    let ethernet_src = mac(0x83);
    let mut stack = host(host_ip, host_mac);
    stack.ndp_table.mark_stale(peer_ip, cached_mac);

    let frame = na_frame_with_tlla(
        peer_ip,
        host_ip,
        peer_ip,
        ethernet_src,
        host_mac,
        None,
        true,
        false,
    );
    assert!(stack.process_frame(&frame).is_empty());
    assert_eq!(stack.ndp_table.lookup(&peer_ip), Some(cached_mac));
    assert_eq!(
        stack.ndp_table.state(&peer_ip),
        Some(NeighborState::Reachable)
    );
}

#[test]
fn override_update_uses_tlla_not_ethernet_source_address() {
    let host_ip = ip6("2001:db8:9::1");
    let peer_ip = ip6("2001:db8:9::2");
    let host_mac = mac(0x91);
    let cached_mac = mac(0x92);
    let advertised_mac = mac(0x93);
    let mut stack = host(host_ip, host_mac);
    stack.ndp_table.confirm_reachable(peer_ip, cached_mac, 0);

    let frame = na_frame_with_tlla(
        peer_ip,
        host_ip,
        peer_ip,
        cached_mac,
        host_mac,
        Some(advertised_mac),
        false,
        true,
    );
    assert!(stack.process_frame(&frame).is_empty());
    assert_eq!(stack.ndp_table.lookup(&peer_ip), Some(advertised_mac));
    assert_eq!(stack.ndp_table.state(&peer_ip), Some(NeighborState::Stale));
}

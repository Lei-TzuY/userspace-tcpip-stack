use std::str::FromStr;

use toy_tcpip::ethernet::{ETHERTYPE_IPV6, EthernetFrame, MacAddress};
use toy_tcpip::icmpv6::{
    Icmpv6Packet, PrefixInformationOption, RouterPreference, ipv6_multicast_mac, link_local_address,
};
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::{Ipv6Address, Ipv6Packet, NEXT_HEADER_ICMPV6};
use toy_tcpip::stack::{IPV6_DAD_RETRANS_TIMER_MS, NetStack, NetStackConfig};

fn ip6(text: &str) -> Ipv6Address {
    Ipv6Address::from_str(text).unwrap()
}

fn stack(mac: MacAddress) -> NetStack {
    NetStack::new(NetStackConfig {
        mac,
        ip: Ipv4Address::new(192, 0, 2, 10),
        ipv6: None,
        subnet_mask: 24,
        gateway: None,
    })
}

fn ra_frame(router_mac: MacAddress, prefix: Ipv6Address, lifetime: u16) -> Vec<u8> {
    let src = link_local_address(router_mac);
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let pio = PrefixInformationOption::new(prefix, 64, true, true, 600, 300);
    let ra =
        Icmpv6Packet::build_router_advertisement(src, dst, 64, lifetime, &[pio], Some(router_mac));
    let packet = Ipv6Packet::serialize(src, dst, NEXT_HEADER_ICMPV6, 255, &ra);
    EthernetFrame::serialize(
        ipv6_multicast_mac(dst).unwrap(),
        router_mac,
        ETHERTYPE_IPV6,
        &packet,
    )
}

fn ra_frame_with_preference(
    router_mac: MacAddress,
    prefix: Ipv6Address,
    lifetime: u16,
    preference: RouterPreference,
) -> Vec<u8> {
    let src = link_local_address(router_mac);
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let pio = PrefixInformationOption::new(prefix, 64, true, true, 600, 300);
    let ra = Icmpv6Packet::build_router_advertisement_with_preference(
        src,
        dst,
        64,
        lifetime,
        preference,
        &[pio],
        Some(router_mac),
    );
    let packet = Ipv6Packet::serialize(src, dst, NEXT_HEADER_ICMPV6, 255, &ra);
    EthernetFrame::serialize(
        ipv6_multicast_mac(dst).unwrap(),
        router_mac,
        ETHERTYPE_IPV6,
        &packet,
    )
}

#[test]
fn active_router_expiry_fails_over_without_new_router_solicitation() {
    let host_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x90]);
    let r1_mac = MacAddress([0x02, 0, 0, 0, 0, 1]);
    let r2_mac = MacAddress([0x02, 0, 0, 0, 0, 2]);
    let r1 = link_local_address(r1_mac);
    let r2 = link_local_address(r2_mac);
    let prefix = ip6("2001:db8:90::");
    let mut s = stack(host_mac);

    assert_eq!(s.process_frame(&ra_frame(r1_mac, prefix, 2)).len(), 1);
    s.step_timers(IPV6_DAD_RETRANS_TIMER_MS);
    assert_eq!(s.ipv6_gateway(), Some(r1));

    // A later RA adds a fallback but must not preempt the current router.
    assert!(s.process_frame(&ra_frame(r2_mac, prefix, 10)).is_empty());
    assert_eq!(s.ipv6_gateway(), Some(r1));

    // R1 expires at t=2s. R2 is selected immediately; no RS is emitted.
    let frames = s.step_timers(2_000);
    assert_eq!(s.ipv6_gateway(), Some(r2));
    assert!(frames.is_empty());
}

#[test]
fn zero_lifetime_withdraws_active_router_and_uses_fallback() {
    let host_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x91]);
    let r1_mac = MacAddress([0x02, 0, 0, 0, 1, 1]);
    let r2_mac = MacAddress([0x02, 0, 0, 0, 1, 2]);
    let r1 = link_local_address(r1_mac);
    let r2 = link_local_address(r2_mac);
    let prefix = ip6("2001:db8:91::");
    let mut s = stack(host_mac);

    s.process_frame(&ra_frame(r1_mac, prefix, 30));
    s.step_timers(IPV6_DAD_RETRANS_TIMER_MS);
    s.process_frame(&ra_frame(r2_mac, prefix, 30));
    assert_eq!(s.ipv6_gateway(), Some(r1));

    assert!(s.process_frame(&ra_frame(r1_mac, prefix, 0)).is_empty());
    assert_eq!(s.ipv6_gateway(), Some(r2));
}

#[test]
fn nud_unreachable_active_router_fails_over_without_new_router_solicitation() {
    let host_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x92]);
    let r1_mac = MacAddress([0x02, 0, 0, 0, 2, 1]);
    let r2_mac = MacAddress([0x02, 0, 0, 0, 2, 2]);
    let r1 = link_local_address(r1_mac);
    let r2 = link_local_address(r2_mac);
    let prefix = ip6("2001:db8:92::");
    let mut s = stack(host_mac);

    s.process_frame(&ra_frame(r1_mac, prefix, 30));
    s.step_timers(IPV6_DAD_RETRANS_TIMER_MS);
    s.process_frame(&ra_frame(r2_mac, prefix, 30));
    assert_eq!(s.ipv6_gateway(), Some(r1));

    // RAs learn routers as STALE. Using R1 starts DELAY without changing the
    // active default router, then three unanswered unicast probes exhaust NUD.
    assert!(
        s.ping6(ip6("2001:db8:ffff::1"), 0x9200, 1, b"nud")
            .is_some()
    );
    assert_eq!(s.step_timers(6_000).len(), 1);
    assert_eq!(s.step_timers(7_000).len(), 1);
    assert_eq!(s.step_timers(8_000).len(), 1);

    let frames = s.step_timers(9_000);
    assert_eq!(s.ipv6_gateway(), Some(r2));
    assert!(frames.is_empty());
}

#[test]
fn nud_unreachable_last_router_restarts_router_discovery() {
    let host_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x93]);
    let router_mac = MacAddress([0x02, 0, 0, 0, 3, 1]);
    let router = link_local_address(router_mac);
    let prefix = ip6("2001:db8:93::");
    let mut s = stack(host_mac);

    s.process_frame(&ra_frame(router_mac, prefix, 30));
    s.step_timers(IPV6_DAD_RETRANS_TIMER_MS);
    assert_eq!(s.ipv6_gateway(), Some(router));

    assert!(
        s.ping6(ip6("2001:db8:ffff::2"), 0x9300, 1, b"nud")
            .is_some()
    );
    assert_eq!(s.step_timers(6_000).len(), 1);
    assert_eq!(s.step_timers(7_000).len(), 1);
    assert_eq!(s.step_timers(8_000).len(), 1);

    let frames = s.step_timers(9_000);
    assert_eq!(s.ipv6_gateway(), None);
    assert_eq!(frames.len(), 1, "last-router loss should emit a fresh RS");
}

// A solicited router NA provides positive NUD reachability evidence.
fn solicited_router_na(
    router_mac: MacAddress,
    router: Ipv6Address,
    host_mac: MacAddress,
    host: Ipv6Address,
) -> Vec<u8> {
    let na = Icmpv6Packet::build_neighbor_advertisement(
        router, host, router, router_mac, true, true, true,
    );
    let packet = Ipv6Packet::serialize(router, host, NEXT_HEADER_ICMPV6, 255, &na);
    EthernetFrame::serialize(host_mac, router_mac, ETHERTYPE_IPV6, &packet)
}

#[test]
fn reachable_router_preempts_non_reachable_active_router() {
    let host_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x94]);
    let r1_mac = MacAddress([0x02, 0, 0, 0, 4, 1]);
    let r2_mac = MacAddress([0x02, 0, 0, 0, 4, 2]);
    let r1 = link_local_address(r1_mac);
    let r2 = link_local_address(r2_mac);
    let prefix = ip6("2001:db8:94::");
    let mut s = stack(host_mac);

    s.process_frame(&ra_frame(r1_mac, prefix, 30));
    s.step_timers(IPV6_DAD_RETRANS_TIMER_MS);
    s.process_frame(&ra_frame(r2_mac, prefix, 30));
    assert_eq!(s.ipv6_gateway(), Some(r1));

    let host = s.config.ipv6.unwrap();
    assert!(
        s.process_frame(&solicited_router_na(r2_mac, r2, host_mac, host))
            .is_empty()
    );
    assert_eq!(s.ipv6_gateway(), Some(r2));
}

#[test]
fn reachable_active_router_remains_stable_when_peer_becomes_reachable() {
    let host_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x95]);
    let r1_mac = MacAddress([0x02, 0, 0, 0, 5, 1]);
    let r2_mac = MacAddress([0x02, 0, 0, 0, 5, 2]);
    let r1 = link_local_address(r1_mac);
    let r2 = link_local_address(r2_mac);
    let prefix = ip6("2001:db8:95::");
    let mut s = stack(host_mac);

    s.process_frame(&ra_frame(r1_mac, prefix, 30));
    s.step_timers(IPV6_DAD_RETRANS_TIMER_MS);
    s.process_frame(&ra_frame(r2_mac, prefix, 30));
    let host = s.config.ipv6.unwrap();

    s.process_frame(&solicited_router_na(r2_mac, r2, host_mac, host));
    assert_eq!(s.ipv6_gateway(), Some(r2));
    s.process_frame(&solicited_router_na(r1_mac, r1, host_mac, host));
    assert_eq!(s.ipv6_gateway(), Some(r2));
}

#[test]
fn higher_router_preference_preempts_equal_reachability() {
    let host_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x96]);
    let medium_mac = MacAddress([0x02, 0, 0, 0, 6, 1]);
    let high_mac = MacAddress([0x02, 0, 0, 0, 6, 2]);
    let medium = link_local_address(medium_mac);
    let high = link_local_address(high_mac);
    let prefix = ip6("2001:db8:96::");
    let mut s = stack(host_mac);

    s.process_frame(&ra_frame_with_preference(
        medium_mac,
        prefix,
        30,
        RouterPreference::Medium,
    ));
    s.step_timers(IPV6_DAD_RETRANS_TIMER_MS);
    assert_eq!(s.ipv6_gateway(), Some(medium));

    s.process_frame(&ra_frame_with_preference(
        high_mac,
        prefix,
        30,
        RouterPreference::High,
    ));
    assert_eq!(s.ipv6_gateway(), Some(high));
}

#[test]
fn nud_reachability_outranks_router_preference() {
    let host_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x97]);
    let high_mac = MacAddress([0x02, 0, 0, 0, 7, 1]);
    let low_mac = MacAddress([0x02, 0, 0, 0, 7, 2]);
    let high = link_local_address(high_mac);
    let low = link_local_address(low_mac);
    let prefix = ip6("2001:db8:97::");
    let mut s = stack(host_mac);

    s.process_frame(&ra_frame_with_preference(
        high_mac,
        prefix,
        30,
        RouterPreference::High,
    ));
    s.step_timers(IPV6_DAD_RETRANS_TIMER_MS);
    s.process_frame(&ra_frame_with_preference(
        low_mac,
        prefix,
        30,
        RouterPreference::Low,
    ));
    assert_eq!(s.ipv6_gateway(), Some(high));

    let host = s.config.ipv6.unwrap();
    s.process_frame(&solicited_router_na(low_mac, low, host_mac, host));
    assert_eq!(s.ipv6_gateway(), Some(low));
}

#[test]
fn router_advertisement_builder_and_parser_preserve_preference() {
    let router_mac = MacAddress([0x02, 0, 0, 0, 8, 1]);
    let src = link_local_address(router_mac);
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let raw = Icmpv6Packet::build_router_advertisement_with_preference(
        src,
        dst,
        64,
        30,
        RouterPreference::High,
        &[],
        Some(router_mac),
    );
    let icmp = Icmpv6Packet::parse(src, dst, &raw, true).unwrap();
    let ra = icmp.validated_router_advertisement(src, 255).unwrap();
    assert_eq!(ra.preference, RouterPreference::High);
}

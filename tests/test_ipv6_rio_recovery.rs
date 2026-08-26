use std::str::FromStr;
use toy_tcpip::ethernet::{ETHERTYPE_IPV6, EthernetFrame, MacAddress};
use toy_tcpip::icmpv6::{
    Icmpv6Packet, NDP_DELAY_FIRST_PROBE_TIME_MS, NDP_RETRANS_TIMER_MS, RouteInformationOption,
    RouterPreference,
};
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::{Ipv6Address, Ipv6Packet, NEXT_HEADER_ICMPV6};
use toy_tcpip::stack::{NetStack, NetStackConfig};

fn ip(s: &str) -> Ipv6Address {
    Ipv6Address::from_str(s).unwrap()
}

fn mac(id: u8) -> MacAddress {
    MacAddress([0x02, 0, 0, 0, 0, id])
}

fn stack() -> NetStack {
    NetStack::new(NetStackConfig {
        mac: mac(0x10),
        ip: Ipv4Address::UNSPECIFIED,
        ipv6: Some(ip("2001:db8:1::10")),
        subnet_mask: 0,
        gateway: None,
    })
}

fn ra_frame(router: Ipv6Address, prefix: Ipv6Address, preference: RouterPreference) -> Vec<u8> {
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let route = RouteInformationOption::new(prefix, 64, preference, 120);
    let ra = Icmpv6Packet::build_router_advertisement_with_routes(
        router,
        dst,
        64,
        1800,
        RouterPreference::Medium,
        &[],
        &[route],
        Some(mac(router.0[15])),
    );
    let packet = Ipv6Packet::serialize(router, dst, NEXT_HEADER_ICMPV6, 255, &ra);
    EthernetFrame::serialize(
        MacAddress([0x33, 0x33, 0, 0, 0, 1]),
        mac(router.0[15]),
        ETHERTYPE_IPV6,
        &packet,
    )
}

fn solicited_na_frame(stack: &NetStack, router: Ipv6Address) -> Vec<u8> {
    let host = stack.config.ipv6.unwrap();
    let na = Icmpv6Packet::build_neighbor_advertisement(
        router,
        host,
        router,
        mac(router.0[15]),
        true,
        true,
        true,
    );
    let packet = Ipv6Packet::serialize(router, host, NEXT_HEADER_ICMPV6, 255, &na);
    EthernetFrame::serialize(stack.config.mac, mac(router.0[15]), ETHERTYPE_IPV6, &packet)
}

#[test]
fn failed_rio_router_recovers_only_after_reachability_confirmation() {
    let mut stack = stack();
    let fallback = ip("fe80::1");
    let preferred = ip("fe80::2");
    let prefix = ip("2001:db8:90::");
    let destination = ip("2001:db8:90::1234");

    stack.process_frame(&ra_frame(fallback, prefix, RouterPreference::Low));
    stack.process_frame(&ra_frame(preferred, prefix, RouterPreference::High));
    assert_eq!(
        stack
            .ipv6_routing_table
            .find_exact(prefix, 64)
            .unwrap()
            .gateway,
        Some(preferred)
    );

    let packet = Ipv6Packet::serialize(stack.config.ipv6.unwrap(), destination, 59, 64, b"nud-rio");
    assert!(stack.send_ip6_packet(destination, packet).is_some());
    for now in [
        NDP_DELAY_FIRST_PROBE_TIME_MS,
        NDP_DELAY_FIRST_PROBE_TIME_MS + NDP_RETRANS_TIMER_MS,
        NDP_DELAY_FIRST_PROBE_TIME_MS + 2 * NDP_RETRANS_TIMER_MS,
    ] {
        assert_eq!(stack.step_timers(now).len(), 1);
    }
    assert!(
        stack
            .step_timers(NDP_DELAY_FIRST_PROBE_TIME_MS + 3 * NDP_RETRANS_TIMER_MS)
            .is_empty()
    );
    assert_eq!(stack.ndp_table.lookup(&preferred), None);
    assert_eq!(
        stack
            .ipv6_routing_table
            .find_exact(prefix, 64)
            .unwrap()
            .gateway,
        Some(fallback)
    );

    let recovered_at = NDP_DELAY_FIRST_PROBE_TIME_MS + 3 * NDP_RETRANS_TIMER_MS;
    stack
        .ndp_table
        .confirm_reachable(fallback, mac(1), recovered_at);
    stack.step_timers(recovered_at);

    // A fresh RA is allowed to restore the failed router's RIO candidate, but
    // the RA's SLLA only recreates a STALE Neighbor Cache entry. It must not
    // displace the fallback that NUD has positively confirmed REACHABLE.
    stack.process_frame(&ra_frame(preferred, prefix, RouterPreference::High));
    assert_eq!(
        stack
            .ipv6_routing_table
            .find_exact(prefix, 64)
            .unwrap()
            .gateway,
        Some(fallback)
    );

    // Once a solicited NA confirms the recovered router is reachable, both
    // candidates have equal reachability and RFC 4191 preference may win again.
    stack.process_frame(&solicited_na_frame(&stack, preferred));
    assert_eq!(
        stack
            .ipv6_routing_table
            .find_exact(prefix, 64)
            .unwrap()
            .gateway,
        Some(preferred)
    );
}

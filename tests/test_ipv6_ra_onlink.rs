use std::str::FromStr;

use toy_tcpip::ethernet::{ETHERTYPE_IPV6, EthernetFrame, MacAddress};
use toy_tcpip::icmpv6::{
    Icmpv6Packet, PrefixInformationOption, ipv6_multicast_mac, link_local_address, slaac_address,
};
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::{Ipv6Address, Ipv6Packet, NEXT_HEADER_ICMPV6};
use toy_tcpip::router::RouteSource;
use toy_tcpip::stack::{IPV6_DAD_RETRANS_TIMER_MS, NetStack, NetStackConfig};

fn ip6(text: &str) -> Ipv6Address {
    Ipv6Address::from_str(text).unwrap()
}

fn ra_frame(
    router_mac: MacAddress,
    prefix: PrefixInformationOption,
    router_lifetime: u16,
) -> Vec<u8> {
    let src = link_local_address(router_mac);
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let ra = Icmpv6Packet::build_router_advertisement(
        src,
        dst,
        64,
        router_lifetime,
        &[prefix],
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

fn host(host_mac: MacAddress) -> NetStack {
    NetStack::new(NetStackConfig {
        mac: host_mac,
        ip: Ipv4Address::new(10, 0, 0, 2),
        ipv6: None,
        subnet_mask: 24,
        gateway: None,
    })
}

#[test]
fn autonomous_without_on_link_uses_default_router_for_same_prefix_peer() {
    let host_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let router_mac = MacAddress([0x02, 0, 0, 0, 1, 1]);
    let router = link_local_address(router_mac);
    let prefix = PrefixInformationOption::new(ip6("2001:db8:44::"), 64, false, true, 3600, 1800);
    let expected = slaac_address(prefix.prefix, 64, host_mac).unwrap();
    let mut stack = host(host_mac);

    let responses = stack.process_frame(&ra_frame(router_mac, prefix, 1800));
    assert_eq!(responses.len(), 1, "RA should start DAD");
    stack.step_timers(IPV6_DAD_RETRANS_TIMER_MS);
    assert_eq!(stack.config.ipv6, Some(expected));

    let peer = ip6("2001:db8:44::beef");
    let route = stack.ipv6_routing_table.lookup(peer).unwrap();
    assert_eq!(route.prefix_len, 0);
    assert_eq!(route.source, RouteSource::Static);
    assert_eq!(route.gateway, Some(router));

    let ping = stack.ping6(peer, 0x4861, 1, b"via-router").unwrap();
    let eth = EthernetFrame::parse(&ping).unwrap();
    assert_eq!(
        eth.dst_mac, router_mac,
        "A=1,L=0 same-prefix traffic must resolve the default router, not the peer"
    );
}

#[test]
fn later_on_link_assertion_adds_route_and_l_zero_does_not_withdraw_it() {
    let host_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let router_mac = MacAddress([0x02, 0, 0, 0, 1, 1]);
    let mut stack = host(host_mac);
    let prefix_addr = ip6("2001:db8:55::");
    let peer = ip6("2001:db8:55::beef");
    // L=0 is not a negative/off-link assertion; it cannot erase prior L=1 knowledge.
    let off_link = PrefixInformationOption::new(prefix_addr, 64, false, true, 3600, 1800);

    stack.process_frame(&ra_frame(router_mac, off_link, 1800));
    stack.step_timers(IPV6_DAD_RETRANS_TIMER_MS);
    assert_eq!(stack.ipv6_routing_table.lookup(peer).unwrap().prefix_len, 0);

    let on_link = PrefixInformationOption::new(prefix_addr, 64, true, true, 3600, 1800);
    stack.process_frame(&ra_frame(router_mac, on_link, 1800));
    let route = stack.ipv6_routing_table.lookup(peer).unwrap();
    assert_eq!(route.prefix_len, 64);
    assert_eq!(route.source, RouteSource::Ra);
    assert_eq!(route.gateway, None);

    stack.process_frame(&ra_frame(router_mac, off_link, 1800));
    let route = stack.ipv6_routing_table.lookup(peer).unwrap();
    assert_eq!(route.prefix_len, 64);
    assert_eq!(route.source, RouteSource::Ra);
}

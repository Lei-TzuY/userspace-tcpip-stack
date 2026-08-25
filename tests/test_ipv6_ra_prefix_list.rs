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

fn host(mac: MacAddress) -> NetStack {
    NetStack::new(NetStackConfig {
        mac,
        ip: Ipv4Address::new(192, 0, 2, 10),
        ipv6: None,
        subnet_mask: 24,
        gateway: None,
    })
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

#[test]
fn on_link_only_pio_installs_route_without_slaac_and_expires() {
    let host_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let router_mac = MacAddress([0x02, 0, 0, 0, 1, 1]);
    let prefix = ip6("2001:db8:60::");
    let peer = ip6("2001:db8:60::beef");
    let pio = PrefixInformationOption::new(prefix, 64, true, false, 2, 0);
    let mut stack = host(host_mac);

    assert!(
        stack
            .process_frame(&ra_frame(router_mac, pio, 0))
            .is_empty()
    );
    assert_eq!(stack.config.ipv6, None, "A=0 must not configure an address");
    let route = stack.ipv6_routing_table.lookup(peer).unwrap();
    assert_eq!(route.prefix_len, 64);
    assert_eq!(route.source, RouteSource::Ra);
    assert_eq!(route.gateway, None);

    stack.step_timers(1_999);
    assert_eq!(
        stack.ipv6_routing_table.lookup(peer).unwrap().source,
        RouteSource::Ra
    );
    stack.step_timers(2_000);
    assert!(stack.ipv6_routing_table.lookup(peer).is_none());
}

#[test]
fn l_zero_does_not_withdraw_but_l_one_zero_lifetime_does() {
    let host_mac = MacAddress([0x00, 0x21, 0x22, 0x23, 0x24, 0x25]);
    let router_mac = MacAddress([0x02, 0, 0, 0, 2, 1]);
    let prefix = ip6("2001:db8:61::");
    let peer = ip6("2001:db8:61::1");
    let mut stack = host(host_mac);

    let on_link = PrefixInformationOption::new(prefix, 64, true, false, 3600, 0);
    stack.process_frame(&ra_frame(router_mac, on_link, 0));
    assert_eq!(
        stack.ipv6_routing_table.lookup(peer).unwrap().source,
        RouteSource::Ra
    );

    let no_statement = PrefixInformationOption::new(prefix, 64, false, false, 0, 0);
    stack.process_frame(&ra_frame(router_mac, no_statement, 0));
    assert_eq!(
        stack.ipv6_routing_table.lookup(peer).unwrap().source,
        RouteSource::Ra,
        "L=0 must not erase prior on-link knowledge"
    );

    let withdraw = PrefixInformationOption::new(prefix, 64, true, false, 0, 0);
    stack.process_frame(&ra_frame(router_mac, withdraw, 0));
    assert!(stack.ipv6_routing_table.lookup(peer).is_none());
}

#[test]
fn slaac_prefix_withdrawal_falls_back_to_router_while_address_survives() {
    let host_mac = MacAddress([0x00, 0x31, 0x32, 0x33, 0x34, 0x35]);
    let router_mac = MacAddress([0x02, 0, 0, 0, 3, 1]);
    let router = link_local_address(router_mac);
    let prefix = ip6("2001:db8:62::");
    let peer = ip6("2001:db8:62::beef");
    let initial = PrefixInformationOption::new(prefix, 64, true, true, 10_800, 7_200);
    let expected = slaac_address(prefix, 64, host_mac).unwrap();
    let mut stack = host(host_mac);

    let dad = stack.process_frame(&ra_frame(router_mac, initial, 1_800));
    assert_eq!(dad.len(), 1);
    stack.step_timers(IPV6_DAD_RETRANS_TIMER_MS);
    assert_eq!(stack.config.ipv6, Some(expected));
    assert_eq!(
        stack.ipv6_routing_table.lookup(peer).unwrap().source,
        RouteSource::Ra
    );

    let withdraw = PrefixInformationOption::new(prefix, 64, true, true, 0, 0);
    assert!(
        stack
            .process_frame(&ra_frame(router_mac, withdraw, 1_800))
            .is_empty()
    );
    assert_eq!(
        stack.config.ipv6,
        Some(expected),
        "RFC 4862 two-hour protection keeps the address valid"
    );
    let route = stack.ipv6_routing_table.lookup(peer).unwrap();
    assert_eq!(route.prefix_len, 0);
    assert_eq!(route.source, RouteSource::Static);
    assert_eq!(route.gateway, Some(router));

    let ping = stack.ping6(peer, 0x4861, 7, b"router-fallback").unwrap();
    let eth = EthernetFrame::parse(&ping).unwrap();
    assert_eq!(eth.dst_mac, router_mac);
}

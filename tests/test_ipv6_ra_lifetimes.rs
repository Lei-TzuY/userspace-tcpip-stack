use std::str::FromStr;

use toy_tcpip::ethernet::{ETHERTYPE_IPV6, EthernetFrame, MacAddress};
use toy_tcpip::icmpv6::{
    Icmpv6Packet, PrefixInformationOption, ipv6_multicast_mac, link_local_address, slaac_address,
};
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::{Ipv6Address, Ipv6Packet, NEXT_HEADER_ICMPV6};
use toy_tcpip::router::RouteSource;
use toy_tcpip::stack::{IPV6_DAD_RETRANS_TIMER_MS, Ipv6SlaacStatus, NetStack, NetStackConfig};

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

fn ra_frame(
    router_mac: MacAddress,
    prefix: Ipv6Address,
    router_lifetime: u16,
    preferred_lifetime: u32,
    valid_lifetime: u32,
) -> Vec<u8> {
    let src = link_local_address(router_mac);
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let pio =
        PrefixInformationOption::new(prefix, 64, true, true, valid_lifetime, preferred_lifetime);
    let ra = Icmpv6Packet::build_router_advertisement(
        src,
        dst,
        64,
        router_lifetime,
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

fn configure_by_ra(
    stack: &mut NetStack,
    router_mac: MacAddress,
    prefix: Ipv6Address,
    router_lifetime: u16,
    preferred_lifetime: u32,
    valid_lifetime: u32,
) -> Ipv6Address {
    let expected = slaac_address(prefix, 64, stack.config.mac).unwrap();
    let frames = stack.process_frame(&ra_frame(
        router_mac,
        prefix,
        router_lifetime,
        preferred_lifetime,
        valid_lifetime,
    ));
    assert_eq!(frames.len(), 1, "initial RA must start DAD");
    stack.step_timers(IPV6_DAD_RETRANS_TIMER_MS);
    assert_eq!(stack.config.ipv6, Some(expected));
    expected
}

#[test]
fn router_preferred_and_valid_lifetimes_expire_independently() {
    let host_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let router_mac = MacAddress([0x02, 0, 0, 0, 1, 1]);
    let prefix = ip6("2001:db8:1::");
    let mut stack = stack(host_mac);
    let address = configure_by_ra(&mut stack, router_mac, prefix, 2, 3, 5);

    assert_eq!(
        stack.ipv6_slaac_status(),
        Ipv6SlaacStatus::Preferred(address)
    );
    assert_eq!(stack.ipv6_gateway(), Some(link_local_address(router_mac)));

    stack.step_timers(1_999);
    assert!(stack.ipv6_gateway().is_some());
    stack.step_timers(2_000);
    assert_eq!(
        stack.ipv6_gateway(),
        None,
        "router lifetime only removes default route"
    );
    assert_eq!(stack.config.ipv6, Some(address));
    assert!(
        !stack
            .ipv6_routing_table
            .routes_from(RouteSource::Connected)
            .is_empty()
    );

    stack.step_timers(3_000);
    assert_eq!(
        stack.ipv6_slaac_status(),
        Ipv6SlaacStatus::Deprecated(address)
    );
    assert_eq!(stack.config.ipv6, Some(address));

    stack.step_timers(4_999);
    assert_eq!(stack.config.ipv6, Some(address));
    stack.step_timers(5_000);
    assert_eq!(
        stack.config.ipv6, None,
        "valid lifetime removes the address"
    );
    assert_eq!(stack.ipv6_slaac_status(), Ipv6SlaacStatus::Unconfigured);
    assert!(
        stack
            .ipv6_routing_table
            .routes_from(RouteSource::Connected)
            .is_empty()
    );
}

#[test]
fn fresh_ra_refreshes_all_three_lifetimes() {
    let host_mac = MacAddress([0x00, 0x21, 0x22, 0x23, 0x24, 0x25]);
    let router_mac = MacAddress([0x02, 0, 0, 0, 2, 1]);
    let prefix = ip6("2001:db8:2::");
    let mut stack = stack(host_mac);
    let address = configure_by_ra(&mut stack, router_mac, prefix, 2, 3, 5);

    stack.step_timers(1_500);
    assert!(
        stack
            .process_frame(&ra_frame(router_mac, prefix, 8, 10, 12))
            .is_empty()
    );

    // All of the original 2/3/5-second deadlines have passed, but the refreshed
    // lifetimes are still active.
    stack.step_timers(5_000);
    assert_eq!(stack.config.ipv6, Some(address));
    assert_eq!(
        stack.ipv6_slaac_status(),
        Ipv6SlaacStatus::Preferred(address)
    );
    assert!(stack.ipv6_gateway().is_some());

    stack.step_timers(9_499);
    assert!(stack.ipv6_gateway().is_some());
    stack.step_timers(9_500);
    assert_eq!(stack.ipv6_gateway(), None);
    assert_eq!(stack.config.ipv6, Some(address));

    stack.step_timers(11_500);
    assert_eq!(
        stack.ipv6_slaac_status(),
        Ipv6SlaacStatus::Deprecated(address)
    );
    stack.step_timers(13_499);
    assert_eq!(stack.config.ipv6, Some(address));
    stack.step_timers(13_500);
    assert_eq!(stack.config.ipv6, None);
}

#[test]
fn zero_router_lifetime_withdraws_default_without_invalidating_prefix() {
    let host_mac = MacAddress([0x00, 0x31, 0x32, 0x33, 0x34, 0x35]);
    let router_mac = MacAddress([0x02, 0, 0, 0, 3, 1]);
    let prefix = ip6("2001:db8:3::");
    let mut stack = stack(host_mac);
    let address = configure_by_ra(&mut stack, router_mac, prefix, 30, 20, 40);
    assert!(stack.ipv6_gateway().is_some());

    stack.step_timers(1_500);
    stack.process_frame(&ra_frame(router_mac, prefix, 0, 20, 40));

    assert_eq!(stack.ipv6_gateway(), None);
    assert_eq!(stack.config.ipv6, Some(address));
    assert_eq!(
        stack.ipv6_slaac_status(),
        Ipv6SlaacStatus::Preferred(address)
    );
    assert!(stack.ipv6_routing_table.find_exact(prefix, 64).is_some());
}

#[test]
fn valid_lifetime_reduction_obeys_rfc4862_two_hour_rule() {
    let host_mac = MacAddress([0x00, 0x41, 0x42, 0x43, 0x44, 0x45]);
    let router_mac = MacAddress([0x02, 0, 0, 0, 4, 1]);
    let prefix = ip6("2001:db8:4::");
    let mut stack = stack(host_mac);
    let address = configure_by_ra(&mut stack, router_mac, prefix, 1_800, 10_000, 10_000);

    // At t=1s the address has almost 10,000s left. An unauthenticated RA trying to
    // slash that to 60s may deprecate it after 60s, but Valid Lifetime is protected
    // at two hours from receipt of the reducing RA.
    stack.process_frame(&ra_frame(router_mac, prefix, 1_800, 60, 60));
    stack.step_timers(61_000);
    assert_eq!(
        stack.ipv6_slaac_status(),
        Ipv6SlaacStatus::Deprecated(address)
    );
    assert_eq!(stack.config.ipv6, Some(address));

    let protected_deadline = IPV6_DAD_RETRANS_TIMER_MS + 2 * 60 * 60 * 1_000;
    stack.step_timers(protected_deadline - 1);
    assert_eq!(stack.config.ipv6, Some(address));
    stack.step_timers(protected_deadline);
    assert_eq!(stack.config.ipv6, None);
}

use std::str::FromStr;
use toy_tcpip::ethernet::{ETHERTYPE_IPV6, EthernetFrame, MacAddress};
use toy_tcpip::icmpv6::{Icmpv6Packet, RouteInformationOption, RouterPreference};
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::{Ipv6Address, Ipv6Packet, NEXT_HEADER_ICMPV6};
use toy_tcpip::router::RouteSource;
use toy_tcpip::stack::{NetStack, NetStackConfig};

fn ip(s: &str) -> Ipv6Address {
    Ipv6Address::from_str(s).unwrap()
}

fn stack() -> NetStack {
    NetStack::new(NetStackConfig {
        mac: MacAddress([0x02, 0, 0, 0, 0, 1]),
        ip: Ipv4Address::UNSPECIFIED,
        ipv6: Some(ip("2001:db8:1::10")),
        subnet_mask: 0,
        gateway: None,
    })
}

fn ra_frame(router: Ipv6Address, route: RouteInformationOption) -> Vec<u8> {
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let ra = Icmpv6Packet::build_router_advertisement_with_routes(
        router,
        dst,
        64,
        1800,
        RouterPreference::Medium,
        &[],
        &[route],
        Some(MacAddress([0x02, 0, 0, 0, 0, router.0[15]])),
    );
    let packet = Ipv6Packet::serialize(router, dst, NEXT_HEADER_ICMPV6, 255, &ra);
    EthernetFrame::serialize(
        MacAddress([0x33, 0x33, 0, 0, 0, 1]),
        MacAddress([0x02, 0, 0, 0, 0, router.0[15]]),
        ETHERTYPE_IPV6,
        &packet,
    )
}

#[test]
fn rio_installs_and_zero_lifetime_withdraws_route() {
    let mut stack = stack();
    let router = ip("fe80::1");
    let prefix = ip("2001:db8:42::");
    stack.process_frame(&ra_frame(
        router,
        RouteInformationOption::new(prefix, 64, RouterPreference::High, 30),
    ));

    let route = stack.ipv6_routing_table.find_exact(prefix, 64).unwrap();
    assert_eq!(route.source, RouteSource::RaRoute);
    assert_eq!(route.gateway, Some(router));

    stack.process_frame(&ra_frame(
        router,
        RouteInformationOption::new(prefix, 64, RouterPreference::High, 0),
    ));
    assert!(stack.ipv6_routing_table.find_exact(prefix, 64).is_none());
}

#[test]
fn rio_prefers_high_and_falls_back_on_expiry() {
    let mut stack = stack();
    let low_router = ip("fe80::1");
    let high_router = ip("fe80::2");
    let prefix = ip("2001:db8:99::");

    stack.process_frame(&ra_frame(
        low_router,
        RouteInformationOption::new(prefix, 64, RouterPreference::Low, 30),
    ));
    stack.process_frame(&ra_frame(
        high_router,
        RouteInformationOption::new(prefix, 64, RouterPreference::High, 2),
    ));
    assert_eq!(
        stack
            .ipv6_routing_table
            .find_exact(prefix, 64)
            .unwrap()
            .gateway,
        Some(high_router)
    );

    stack.step_timers(2_000);
    assert_eq!(
        stack
            .ipv6_routing_table
            .find_exact(prefix, 64)
            .unwrap()
            .gateway,
        Some(low_router)
    );
}

#[test]
fn on_link_pio_route_still_outranks_rio_candidate() {
    use toy_tcpip::icmpv6::PrefixInformationOption;

    let mut stack = stack();
    let router = ip("fe80::1");
    let prefix = ip("2001:db8:77::");
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let pio = PrefixInformationOption::new(prefix, 64, true, false, 60, 0);
    let rio = RouteInformationOption::new(prefix, 64, RouterPreference::High, 60);
    let ra = Icmpv6Packet::build_router_advertisement_with_routes(
        router,
        dst,
        64,
        1800,
        RouterPreference::Medium,
        &[pio],
        &[rio],
        None,
    );
    let packet = Ipv6Packet::serialize(router, dst, NEXT_HEADER_ICMPV6, 255, &ra);
    let frame = EthernetFrame::serialize(
        MacAddress([0x33, 0x33, 0, 0, 0, 1]),
        MacAddress([0x02, 0, 0, 0, 0, 1]),
        ETHERTYPE_IPV6,
        &packet,
    );
    stack.process_frame(&frame);

    let route = stack
        .ipv6_routing_table
        .lookup(ip("2001:db8:77::1234"))
        .unwrap();
    assert_eq!(route.source, RouteSource::Ra);
    assert_eq!(route.gateway, None);
}

#[test]
fn clearing_ipv6_interface_removes_learned_rio_routes() {
    let mut stack = stack();
    let router = ip("fe80::1");
    let prefix = ip("2001:db8:55::");
    stack.process_frame(&ra_frame(
        router,
        RouteInformationOption::new(prefix, 64, RouterPreference::Medium, 60),
    ));
    assert!(stack.ipv6_routing_table.find_exact(prefix, 64).is_some());

    stack.clear_ipv6_interface();
    assert!(stack.ipv6_routing_table.find_exact(prefix, 64).is_none());
    assert!(
        stack
            .ipv6_routing_table
            .routes_from(RouteSource::RaRoute)
            .is_empty()
    );
}

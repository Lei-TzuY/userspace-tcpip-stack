use userspace_tcpip_stack::ipv6::Ipv6Address;
use userspace_tcpip_stack::router::RouteSource;
use userspace_tcpip_stack::router_ipv6::Ipv6RoutingTable;
use std::str::FromStr;

fn ip(value: &str) -> Ipv6Address {
    Ipv6Address::from_str(value).unwrap()
}

#[test]
fn single_path_replacement_collapses_existing_multipath_candidates() {
    let mut table = Ipv6RoutingTable::new();
    let prefix = ip("2001:db8:42::");
    let router_a = ip("fe80::1");
    let router_b = ip("fe80::2");

    table.add_multipath_route_from(
        prefix,
        64,
        Some(router_a),
        "eth0",
        RouteSource::Bgp,
    );
    table.add_multipath_route_from(
        prefix,
        64,
        Some(router_b),
        "eth1",
        RouteSource::Bgp,
    );

    table.add_route_from(
        prefix,
        64,
        Some(router_b),
        "eth1",
        RouteSource::Bgp,
    );

    let routes = table.routes_from(RouteSource::Bgp);
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].destination, prefix);
    assert_eq!(routes[0].prefix_len, 64);
    assert_eq!(routes[0].gateway, Some(router_b));
    assert_eq!(routes[0].interface, "eth1");
}

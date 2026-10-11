use std::str::FromStr;

use toy_tcpip::ethernet::MacAddress;
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::Ipv6Address;
use toy_tcpip::ipv6::{Ipv6Packet, NEXT_HEADER_UDP};
use toy_tcpip::router::RouteSource;
use toy_tcpip::router_ipv6::Ipv6RoutingTable;
use toy_tcpip::stack::{NetStack, NetStackConfig};

fn ip(value: &str) -> Ipv6Address {
    Ipv6Address::from_str(value).unwrap()
}

#[test]
fn single_path_replacement_collapses_existing_multipath_candidates() {
    let mut table = Ipv6RoutingTable::new();
    let prefix = ip("2001:db8:42::");
    let router_a = ip("fe80::1");
    let router_b = ip("fe80::2");

    table.add_multipath_route_from(prefix, 64, Some(router_a), "eth0", RouteSource::Bgp);
    table.add_multipath_route_from(prefix, 64, Some(router_b), "eth1", RouteSource::Bgp);

    table.add_route_from(prefix, 64, Some(router_b), "eth1", RouteSource::Bgp);

    let routes = table.routes_from(RouteSource::Bgp);
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].destination, prefix);
    assert_eq!(routes[0].prefix_len, 64);
    assert_eq!(routes[0].gateway, Some(router_b));
    assert_eq!(routes[0].interface, "eth1");
}

#[test]
fn replacement_is_scoped_to_the_normalized_prefix_and_source() {
    let mut table = Ipv6RoutingTable::new();
    let prefix = ip("2001:db8:42::");
    let host = ip("2001:db8:42::7");
    let other_prefix = ip("2001:db8:43::");
    let gateway = ip("fe80::3");

    table.add_multipath_route_from(host, 64, Some(ip("fe80::1")), "eth0", RouteSource::Bgp);
    table.add_multipath_route_from(prefix, 64, Some(ip("fe80::2")), "eth1", RouteSource::Bgp);
    table.add_route_from(prefix, 64, None, "connected", RouteSource::Connected);
    table.add_route_from(host, 128, None, "host", RouteSource::Bgp);
    table.add_route_from(other_prefix, 64, None, "other", RouteSource::Bgp);
    let protected = [
        table.routes_from(RouteSource::Connected)[0].clone(),
        table.find_exact(host, 128).unwrap().clone(),
        table.find_exact(other_prefix, 64).unwrap().clone(),
    ];

    table.add_route_from(
        ip("2001:db8:42::99"),
        64,
        Some(gateway),
        "eth2",
        RouteSource::Bgp,
    );

    assert_eq!(table.all_routes().len(), 4);
    for route in &protected {
        assert!(table.all_routes().contains(route));
    }
    let replacement = table
        .routes_from(RouteSource::Bgp)
        .into_iter()
        .find(|route| route.destination == prefix && route.prefix_len == 64)
        .unwrap();
    assert_eq!(replacement.gateway, Some(gateway));
    assert_eq!(replacement.interface, "eth2");
}

#[test]
fn netstack_replacement_stops_forwarding_through_stale_ecmp_next_hops() {
    let local = ip("2001:db8:1::10");
    let prefix = ip("2001:db8:42::");
    let old_a = ip("fe80::1");
    let old_b = ip("fe80::2");
    let replacement = ip("fe80::3");
    let replacement_mac = MacAddress([0x02, 0, 0, 0, 0, 3]);
    let mut stack = NetStack::new(NetStackConfig {
        mac: MacAddress([0x02, 0, 0, 0, 0, 10]),
        ip: Ipv4Address::new(192, 0, 2, 10),
        ipv6: Some(local),
        subnet_mask: 24,
        gateway: None,
    });
    for (gateway, last_byte) in [(old_a, 1), (old_b, 2), (replacement, 3)] {
        stack
            .ndp_table
            .insert(gateway, MacAddress([0x02, 0, 0, 0, 0, last_byte]));
    }
    for gateway in [old_a, old_b] {
        stack.ipv6_routing_table.add_multipath_route_from(
            prefix,
            64,
            Some(gateway),
            "eth0",
            RouteSource::Bgp,
        );
    }
    stack.ipv6_routing_table.add_route_from(
        prefix,
        64,
        Some(replacement),
        "eth0",
        RouteSource::Bgp,
    );

    // Exercise both ECMP hash buckets: no flow may keep using an old candidate.
    for host in 1..=16 {
        let destination = ip(&format!("2001:db8:42::{host:x}"));
        let packet = Ipv6Packet::serialize(local, destination, NEXT_HEADER_UDP, 64, b"replacement");
        let frame = stack.send_ip6_packet(destination, packet).unwrap();
        assert_eq!(&frame[..6], &replacement_mac.0);
    }
    assert!(stack.pending_ndp_packets.is_empty());
}

#[test]
fn replacement_preserves_insertion_order_between_equal_cost_sources() {
    let mut table = Ipv6RoutingTable::new();
    let prefix = ip("2001:db8:42::");
    table.add_route_from(prefix, 64, None, "connected", RouteSource::Connected);
    table.add_route_from(prefix, 64, None, "ra", RouteSource::Ra);
    table.add_multipath_route_from(prefix, 64, None, "connected-alt", RouteSource::Connected);

    table.add_route_from(prefix, 64, None, "connected-new", RouteSource::Connected);

    let best = table.lookup_best_routes(ip("2001:db8:42::99"));
    assert_eq!(best.len(), 2);
    assert_eq!(best[0].source, RouteSource::Connected);
    assert_eq!(best[0].interface, "connected-new");
    assert_eq!(best[1].source, RouteSource::Ra);
    assert_eq!(best[1].interface, "ra");
}

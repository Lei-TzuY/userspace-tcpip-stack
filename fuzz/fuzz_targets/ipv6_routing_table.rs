#![no_main]

use libfuzzer_sys::fuzz_target;
use toy_tcpip::ipv6::Ipv6Address;
use toy_tcpip::router::RouteSource;
use toy_tcpip::router_ipv6::{Ipv6RouteEntry, Ipv6RoutingTable};

fn source(byte: u8) -> RouteSource {
    match byte % 7 {
        0 => RouteSource::Connected,
        1 => RouteSource::Ra,
        2 => RouteSource::RaRoute,
        3 => RouteSource::Static,
        4 => RouteSource::Bgp,
        5 => RouteSource::Ospf,
        _ => RouteSource::Rip,
    }
}

fn address(bytes: &[u8]) -> Ipv6Address {
    let mut value = [0u8; 16];
    value.copy_from_slice(&bytes[..16]);
    Ipv6Address(value)
}

fn mask(address: Ipv6Address, prefix_len: u8) -> Ipv6Address {
    let prefix_len = prefix_len.min(128);
    let mut bytes = address.0;
    let whole = (prefix_len / 8) as usize;
    let rem = prefix_len % 8;
    if rem != 0 && whole < bytes.len() {
        bytes[whole] &= 0xff << (8 - rem);
    }
    let clear_from = whole + usize::from(rem != 0);
    for byte in &mut bytes[clear_from..] {
        *byte = 0;
    }
    Ipv6Address(bytes)
}

fuzz_target!(|data: &[u8]| {
    let mut table = Ipv6RoutingTable::new();
    let mut offset = 0usize;

    while offset + 36 <= data.len() {
        let op = data[offset];
        let destination = address(&data[offset + 1..offset + 17]);
        let prefix_len = data[offset + 17];
        let route_source = source(data[offset + 18]);
        let gateway = address(&data[offset + 19..offset + 35]);
        let iface = if data[offset + 35] & 1 == 0 { "eth0" } else { "eth1" };
        let next_hop = (op & 0x04 != 0).then_some(gateway);

        match op % 4 {
            0 => table.add_route_from(
                destination,
                prefix_len,
                next_hop,
                iface,
                route_source,
            ),
            1 => table.add_multipath_route_from(
                destination,
                prefix_len,
                next_hop,
                iface,
                route_source,
            ),
            2 => {
                table.remove_route(destination, prefix_len, route_source);
            }
            _ => {
                table.remove_route_via(
                    destination,
                    prefix_len,
                    next_hop,
                    iface,
                    route_source,
                );
            }
        }
        offset += 36;
    }

    for route in table.all_routes() {
        assert!(route.prefix_len <= 128);
        assert_eq!(route.destination, mask(route.destination, route.prefix_len));
    }
    for pair in table.all_routes().windows(2) {
        assert!(pair[0].prefix_len > pair[1].prefix_len
            || (pair[0].prefix_len == pair[1].prefix_len
                && pair[0].distance() <= pair[1].distance()));
    }
    for (i, left) in table.all_routes().iter().enumerate() {
        for right in &table.all_routes()[i + 1..] {
            assert!(left.destination != right.destination
                || left.prefix_len != right.prefix_len
                || left.gateway != right.gateway
                || left.interface != right.interface
                || left.source != right.source);
        }
    }

    let query = if offset + 16 <= data.len() {
        address(&data[offset..offset + 16])
    } else {
        Ipv6Address([0; 16])
    };
    let flow_hash = if offset + 24 <= data.len() {
        u64::from_le_bytes(data[offset + 16..offset + 24].try_into().unwrap())
    } else {
        0
    };

    let expected: Option<&Ipv6RouteEntry> = table
        .all_routes()
        .iter()
        .filter(|route| route.matches(query))
        .min_by_key(|route| (u8::MAX - route.prefix_len, route.distance()));

    let best = table.lookup_best_routes(query);
    if let Some(expected) = expected {
        assert!(!best.is_empty());
        assert!(best.iter().all(|route| {
            route.matches(query)
                && route.prefix_len == expected.prefix_len
                && route.distance() == expected.distance()
        }));
        let expected_count = table
            .all_routes()
            .iter()
            .filter(|route| {
                route.matches(query)
                    && route.prefix_len == expected.prefix_len
                    && route.distance() == expected.distance()
            })
            .count();
        assert_eq!(best.len(), expected_count);

        let default_selected = table.lookup(query).unwrap();
        assert!(best.contains(&default_selected));

        let selected = table.lookup_best_route_by_hash(query, flow_hash).unwrap();
        assert_eq!(selected, best[(flow_hash % best.len() as u64) as usize]);
    } else {
        assert!(table.lookup(query).is_none());
        assert!(best.is_empty());
        assert!(table.lookup_best_route_by_hash(query, flow_hash).is_none());
    }
});

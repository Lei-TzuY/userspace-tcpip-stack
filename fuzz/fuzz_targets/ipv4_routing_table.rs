#![no_main]

use libfuzzer_sys::fuzz_target;
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::router::{RouteEntry, RouteSource, RoutingTable};

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

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    let mut table = RoutingTable::new();
    let mut offset = 0usize;

    while offset + 12 <= data.len() {
        let op = data[offset];
        let destination = Ipv4Address::new(
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
        );
        let prefix_len = data[offset + 5];
        let route_source = source(data[offset + 6]);
        let gateway = Ipv4Address::new(
            data[offset + 7],
            data[offset + 8],
            data[offset + 9],
            data[offset + 10],
        );
        let iface = if data[offset + 11] & 1 == 0 { "eth0" } else { "eth1" };

        match op % 3 {
            0 | 1 => table.add_route_from(
                destination,
                prefix_len,
                (op & 1 != 0).then_some(gateway),
                iface,
                route_source,
            ),
            _ => {
                table.remove_route(destination, prefix_len, route_source);
            }
        }
        offset += 12;
    }

    // Table state must stay canonical and deterministically ordered after arbitrary
    // add/replace/remove sequences.
    for route in table.all_routes() {
        assert!(route.prefix_len <= 32);
    }
    for pair in table.all_routes().windows(2) {
        assert!(pair[0].prefix_len > pair[1].prefix_len
            || (pair[0].prefix_len == pair[1].prefix_len
                && pair[0].distance() <= pair[1].distance()));
    }
    for (i, left) in table.all_routes().iter().enumerate() {
        for right in &table.all_routes()[i + 1..] {
            assert!(left.source != right.source
                || left.prefix_len != right.prefix_len
                || left.destination.mask(left.prefix_len) != right.destination.mask(right.prefix_len));
        }
    }

    let query = if offset + 4 <= data.len() {
        Ipv4Address::new(data[offset], data[offset + 1], data[offset + 2], data[offset + 3])
    } else {
        Ipv4Address::UNSPECIFIED
    };

    let expected: Option<&RouteEntry> = table
        .all_routes()
        .iter()
        .filter(|route| route.matches(query))
        .min_by_key(|route| (u8::MAX - route.prefix_len, route.distance()));
    assert_eq!(table.lookup(query), expected);
});

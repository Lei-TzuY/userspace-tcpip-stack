use std::env;
use std::process::ExitCode;
use std::str::FromStr;

use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::router::{RouteEntry, RouteSource, RoutingTable};

const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn fnv1a_extend(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash = (hash ^ u64::from(*byte)).wrapping_mul(FNV_PRIME);
    }
    hash
}

fn route_score(flow_hash: u64, route: &RouteEntry) -> u64 {
    let mut hash = fnv1a_extend(FNV_OFFSET_BASIS, &flow_hash.to_be_bytes());
    hash = fnv1a_extend(
        hash,
        &route
            .destination
            .mask(route.prefix_len)
            .to_u32()
            .to_be_bytes(),
    );
    hash = fnv1a_extend(hash, &[route.prefix_len]);
    match route.gateway {
        Some(gateway) => {
            hash = fnv1a_extend(hash, &[1]);
            hash = fnv1a_extend(hash, &gateway.to_u32().to_be_bytes());
        }
        None => hash = fnv1a_extend(hash, &[0]),
    }
    hash = fnv1a_extend(hash, route.interface.as_bytes());
    fnv1a_extend(hash, route.source.as_str().as_bytes())
}

fn route_identity_cmp(left: &RouteEntry, right: &RouteEntry) -> std::cmp::Ordering {
    let left_gateway = left.gateway.map(|gateway| gateway.to_u32());
    let right_gateway = right.gateway.map(|gateway| gateway.to_u32());
    left.destination
        .to_u32()
        .cmp(&right.destination.to_u32())
        .then(left.prefix_len.cmp(&right.prefix_len))
        .then(left_gateway.cmp(&right_gateway))
        .then(left.interface.cmp(&right.interface))
        .then(left.source.as_str().cmp(right.source.as_str()))
}

fn select_resilient_route(
    table: &RoutingTable,
    destination: Ipv4Address,
    flow_hash: u64,
) -> Option<&RouteEntry> {
    table
        .lookup_best_routes(destination)
        .into_iter()
        .max_by(|left, right| {
            route_score(flow_hash, left)
                .cmp(&route_score(flow_hash, right))
                .then_with(|| route_identity_cmp(left, right))
        })
}

fn parse_route_spec(spec: &str) -> Result<(Ipv4Address, u8, Option<Ipv4Address>, String), String> {
    let (prefix, rest) = spec
        .split_once('=')
        .ok_or_else(|| format!("invalid route '{spec}': expected PREFIX/LEN=GATEWAY@IFACE"))?;
    let (address, prefix_len) = prefix
        .split_once('/')
        .ok_or_else(|| format!("invalid prefix '{prefix}'"))?;
    let (gateway, interface) = rest
        .split_once('@')
        .ok_or_else(|| format!("invalid next hop '{rest}': expected GATEWAY@IFACE"))?;
    if interface.is_empty() {
        return Err("interface must not be empty".to_string());
    }
    let destination = Ipv4Address::from_str(address)?;
    let prefix_len = prefix_len
        .parse::<u8>()
        .map_err(|_| format!("invalid prefix length '{prefix_len}'"))?;
    if prefix_len > 32 {
        return Err(format!("invalid IPv4 prefix length {prefix_len}"));
    }
    let gateway = if gateway == "on-link" {
        None
    } else {
        Some(Ipv4Address::from_str(gateway)?)
    };
    Ok((destination, prefix_len, gateway, interface.to_string()))
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let destination = args
        .next()
        .ok_or_else(|| {
            "usage: ipv4_resilient_ecmp DESTINATION FLOW_HASH PREFIX/LEN=GATEWAY@IFACE [ROUTE ...]"
                .to_string()
        })?
        .parse::<Ipv4Address>()?;
    let flow_hash = args
        .next()
        .ok_or_else(|| "missing FLOW_HASH".to_string())?
        .parse::<u64>()
        .map_err(|_| "FLOW_HASH must be an unsigned 64-bit integer".to_string())?;

    let mut table = RoutingTable::new();
    let mut route_count = 0usize;
    for spec in args {
        let (prefix, prefix_len, gateway, interface) = parse_route_spec(&spec)?;
        table.add_multipath_route_from(
            prefix,
            prefix_len,
            gateway,
            &interface,
            RouteSource::Static,
        );
        route_count += 1;
    }
    if route_count == 0 {
        return Err("at least one route is required".to_string());
    }

    let route = select_resilient_route(&table, destination, flow_hash)
        .ok_or_else(|| format!("no route for {destination}"))?;
    println!(
        "{} via {} dev {}",
        destination,
        route.next_hop(destination),
        route.interface
    );
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ipv4_resilient_ecmp: {error}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    fn add_member(table: &mut RoutingTable, gateway_octet: u8, interface: &str) {
        table.add_multipath_route_from(
            Ipv4Address::new(203, 0, 113, 0),
            24,
            Some(Ipv4Address::new(192, 0, 2, gateway_octet)),
            interface,
            RouteSource::Static,
        );
    }

    fn three_member_table() -> RoutingTable {
        let mut table = RoutingTable::new();
        add_member(&mut table, 1, "wan-a");
        add_member(&mut table, 2, "wan-b");
        add_member(&mut table, 3, "wan-c");
        table
    }

    #[test]
    fn resilient_selection_is_insertion_order_independent() {
        let mut forward = RoutingTable::new();
        add_member(&mut forward, 1, "wan-a");
        add_member(&mut forward, 2, "wan-b");
        add_member(&mut forward, 3, "wan-c");

        let mut reverse = RoutingTable::new();
        add_member(&mut reverse, 3, "wan-c");
        add_member(&mut reverse, 2, "wan-b");
        add_member(&mut reverse, 1, "wan-a");

        let destination = Ipv4Address::new(203, 0, 113, 77);
        for flow_hash in 0..512 {
            assert_eq!(
                select_resilient_route(&forward, destination, flow_hash)
                    .unwrap()
                    .gateway,
                select_resilient_route(&reverse, destination, flow_hash)
                    .unwrap()
                    .gateway
            );
        }
    }

    #[test]
    fn withdrawing_member_preserves_surviving_flow_affinity() {
        let mut table = three_member_table();
        let destination = Ipv4Address::new(203, 0, 113, 77);
        let removed = Ipv4Address::new(192, 0, 2, 2);
        let mut before = HashMap::new();
        let mut used = HashSet::new();

        for flow_hash in 0..2048 {
            let gateway = select_resilient_route(&table, destination, flow_hash)
                .unwrap()
                .gateway
                .unwrap();
            before.insert(flow_hash, gateway);
            used.insert(gateway);
        }
        assert_eq!(used.len(), 3, "flow sample should exercise all ECMP members");

        assert!(table.remove_route_via(
            Ipv4Address::new(203, 0, 113, 0),
            24,
            Some(removed),
            "wan-b",
            RouteSource::Static,
        ));

        for (flow_hash, old_gateway) in before {
            let new_gateway = select_resilient_route(&table, destination, flow_hash)
                .unwrap()
                .gateway
                .unwrap();
            if old_gateway != removed {
                assert_eq!(new_gateway, old_gateway);
            } else {
                assert_ne!(new_gateway, removed);
            }
        }
    }

    #[test]
    fn selection_stays_bounded_to_best_lpm_and_distance() {
        let mut table = three_member_table();
        table.add_multipath_route_from(
            Ipv4Address::new(203, 0, 0, 0),
            16,
            Some(Ipv4Address::new(192, 0, 2, 99)),
            "less-specific",
            RouteSource::Static,
        );
        table.add_multipath_route_from(
            Ipv4Address::new(203, 0, 113, 0),
            24,
            Some(Ipv4Address::new(192, 0, 2, 100)),
            "worse-distance",
            RouteSource::Ospf,
        );

        let destination = Ipv4Address::new(203, 0, 113, 77);
        for flow_hash in 0..256 {
            let selected = select_resilient_route(&table, destination, flow_hash).unwrap();
            assert_eq!(selected.prefix_len, 24);
            assert_eq!(selected.source, RouteSource::Static);
        }
    }

    #[test]
    fn route_spec_validation_rejects_invalid_prefix() {
        assert!(parse_route_spec("203.0.113.0/33=192.0.2.1@wan0").is_err());
    }
}

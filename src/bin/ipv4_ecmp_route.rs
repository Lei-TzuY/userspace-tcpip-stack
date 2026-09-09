use std::env;
use std::process::ExitCode;
use std::str::FromStr;

use toy_tcpip::ipv4::{IpProtocol, Ipv4Address, Ipv4Packet};
use toy_tcpip::router::{Ipv4FlowKey, RouteEntry, RouteSource, RoutingTable};

fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    if !input.len().is_multiple_of(2) {
        return Err("packet hex must contain an even number of digits".to_string());
    }
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| "packet hex is not ASCII")?;
            u8::from_str_radix(text, 16).map_err(|_| format!("invalid hex byte: {text}"))
        })
        .collect()
}

fn transport_ports(packet: &Ipv4Packet<'_>) -> (u16, u16) {
    if packet.header.fragment_offset != 0 {
        return (0, 0);
    }
    match packet.header.protocol {
        IpProtocol::Tcp | IpProtocol::Udp if packet.payload.len() >= 4 => (
            u16::from_be_bytes([packet.payload[0], packet.payload[1]]),
            u16::from_be_bytes([packet.payload[2], packet.payload[3]]),
        ),
        _ => (0, 0),
    }
}

fn flow_key(packet: &Ipv4Packet<'_>) -> Ipv4FlowKey {
    let (source_port, destination_port) = transport_ports(packet);
    Ipv4FlowKey::new(
        packet.header.src_ip,
        packet.header.dst_ip,
        packet.header.protocol.to_u8(),
        source_port,
        destination_port,
    )
}

fn select_route<'a>(table: &'a RoutingTable, packet_bytes: &[u8]) -> Result<&'a RouteEntry, String> {
    let packet = Ipv4Packet::parse(packet_bytes, true).map_err(|error| error.to_string())?;
    table
        .lookup_best_route_for_flow(flow_key(&packet))
        .ok_or_else(|| format!("no route for {}", packet.header.dst_ip))
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
    let packet_hex = args.next().ok_or_else(|| {
        "usage: ipv4_ecmp_route PACKET_HEX PREFIX/LEN=GATEWAY@IFACE [ROUTE ...]".to_string()
    })?;
    let packet_bytes = decode_hex(&packet_hex)?;
    let mut table = RoutingTable::new();
    let mut route_count = 0usize;
    for spec in args {
        let (destination, prefix_len, gateway, interface) = parse_route_spec(&spec)?;
        table.add_multipath_route_from(
            destination,
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

    let route = select_route(&table, &packet_bytes)?;
    let packet = Ipv4Packet::parse(&packet_bytes, true).map_err(|error| error.to_string())?;
    println!(
        "{} via {} dev {}",
        packet.header.dst_ip,
        route.next_hop(packet.header.dst_ip),
        route.interface
    );
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ipv4_ecmp_route: {error}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use toy_tcpip::ipv4::{IP_PROTO_ICMP, IP_PROTO_UDP};

    fn table() -> RoutingTable {
        let mut table = RoutingTable::new();
        let prefix = Ipv4Address::new(203, 0, 113, 0);
        table.add_multipath_route_from(
            prefix,
            24,
            Some(Ipv4Address::new(192, 0, 2, 1)),
            "wan-a",
            RouteSource::Static,
        );
        table.add_multipath_route_from(
            prefix,
            24,
            Some(Ipv4Address::new(192, 0, 2, 2)),
            "wan-b",
            RouteSource::Static,
        );
        table
    }

    fn udp_packet(source_port: u16) -> Vec<u8> {
        let mut udp = Vec::from(source_port.to_be_bytes());
        udp.extend_from_slice(&443u16.to_be_bytes());
        udp.extend_from_slice(&[0, 8, 0, 0]);
        Ipv4Packet::serialize(
            Ipv4Address::new(198, 51, 100, 9),
            Ipv4Address::new(203, 0, 113, 77),
            IP_PROTO_UDP,
            7,
            64,
            &udp,
        )
    }

    #[test]
    fn packet_bytes_drive_stable_ecmp_affinity() {
        let table = table();
        let packet = udp_packet(40_000);
        let first = select_route(&table, &packet).unwrap();
        let second = select_route(&table, &packet).unwrap();
        assert_eq!(first.gateway, second.gateway);
    }

    #[test]
    fn transport_entropy_can_reach_both_ecmp_members() {
        let table = table();
        let mut gateways = std::collections::HashSet::new();
        for source_port in 40_000..40_128 {
            gateways.insert(select_route(&table, &udp_packet(source_port)).unwrap().gateway);
        }
        assert_eq!(gateways.len(), 2);
    }

    #[test]
    fn non_transport_packet_uses_zero_ports() {
        let bytes = Ipv4Packet::serialize(
            Ipv4Address::new(198, 51, 100, 9),
            Ipv4Address::new(203, 0, 113, 77),
            IP_PROTO_ICMP,
            8,
            64,
            &[8, 0, 0, 0],
        );
        let packet = Ipv4Packet::parse(&bytes, true).unwrap();
        let key = flow_key(&packet);
        assert_eq!(key.source_port, 0);
        assert_eq!(key.destination_port, 0);
    }

    #[test]
    fn route_specs_support_on_link_and_reject_bad_prefixes() {
        let parsed = parse_route_spec("203.0.113.0/24=on-link@lan0").unwrap();
        assert_eq!(parsed.0, Ipv4Address::new(203, 0, 113, 0));
        assert_eq!(parsed.1, 24);
        assert_eq!(parsed.2, None);
        assert_eq!(parsed.3, "lan0");
        assert!(parse_route_spec("203.0.113.0/33=192.0.2.1@wan0").is_err());
    }
}
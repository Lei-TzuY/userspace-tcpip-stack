use std::collections::HashMap;
use std::env;
use std::process::ExitCode;
use std::str::FromStr;

use toy_tcpip::arp::ArpPacket;
use toy_tcpip::ethernet::{ETHERTYPE_ARP, ETHERTYPE_IPV4, EthernetFrame, MacAddress};
use toy_tcpip::ipv4::{IpProtocol, Ipv4Address, Ipv4Packet};
use toy_tcpip::router::{Ipv4FlowKey, RouteSource, RoutingTable};

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

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
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

fn parse_arp_spec(spec: &str) -> Result<(Ipv4Address, MacAddress), String> {
    let (ip, mac) = spec
        .split_once('=')
        .ok_or_else(|| format!("invalid ARP entry '{spec}': expected IP=MAC"))?;
    Ok((Ipv4Address::from_str(ip)?, MacAddress::from_str(mac)?))
}

fn forward_packet(
    table: &RoutingTable,
    neighbors: &HashMap<Ipv4Address, MacAddress>,
    source_mac: MacAddress,
    packet_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    let packet = Ipv4Packet::parse(packet_bytes, true).map_err(|error| error.to_string())?;
    let route = table
        .lookup_best_route_for_flow(flow_key(&packet))
        .ok_or_else(|| format!("no route for {}", packet.header.dst_ip))?;
    let next_hop = route.next_hop(packet.header.dst_ip);

    if let Some(destination_mac) = neighbors.get(&next_hop).copied() {
        return Ok(EthernetFrame::serialize(
            destination_mac,
            source_mac,
            ETHERTYPE_IPV4,
            packet_bytes,
        ));
    }

    let request = ArpPacket::build_request(source_mac, packet.header.src_ip.0, next_hop.0);
    Ok(EthernetFrame::serialize(
        MacAddress::BROADCAST,
        source_mac,
        ETHERTYPE_ARP,
        &request.serialize(),
    ))
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let source_mac = MacAddress::from_str(&args.next().ok_or_else(|| {
        "usage: ipv4_ecmp_forward SOURCE_MAC PACKET_HEX ROUTE... [--arp IP=MAC ...]".to_string()
    })?)?;
    let packet_hex = args.next().ok_or_else(|| {
        "usage: ipv4_ecmp_forward SOURCE_MAC PACKET_HEX ROUTE... [--arp IP=MAC ...]".to_string()
    })?;
    let packet_bytes = decode_hex(&packet_hex)?;

    let mut table = RoutingTable::new();
    let mut neighbors = HashMap::new();
    let mut route_count = 0usize;
    let mut parsing_arp = false;
    for argument in args {
        if argument == "--arp" {
            parsing_arp = true;
            continue;
        }
        if parsing_arp {
            let (ip, mac) = parse_arp_spec(&argument)?;
            neighbors.insert(ip, mac);
        } else {
            let (destination, prefix_len, gateway, interface) = parse_route_spec(&argument)?;
            table.add_multipath_route_from(
                destination,
                prefix_len,
                gateway,
                &interface,
                RouteSource::Static,
            );
            route_count += 1;
        }
    }
    if route_count == 0 {
        return Err("at least one route is required".to_string());
    }

    let frame = forward_packet(&table, &neighbors, source_mac, &packet_bytes)?;
    println!("{}", encode_hex(&frame));
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ipv4_ecmp_forward: {error}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use toy_tcpip::ethernet::EtherType;
    use toy_tcpip::ipv4::IP_PROTO_UDP;

    fn packet(source_port: u16) -> Vec<u8> {
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

    #[test]
    fn resolved_ecmp_next_hop_emits_ipv4_ethernet_frame() {
        let table = table();
        let packet = packet(40_000);
        let parsed = Ipv4Packet::parse(&packet, true).unwrap();
        let selected = table.lookup_best_route_for_flow(flow_key(&parsed)).unwrap();
        let next_hop = selected.next_hop(parsed.header.dst_ip);
        let source_mac = MacAddress::new([0x02, 0, 0, 0, 0, 1]);
        let destination_mac = MacAddress::new([0x02, 0, 0, 0, 0, 2]);
        let neighbors = HashMap::from([(next_hop, destination_mac)]);

        let frame = forward_packet(&table, &neighbors, source_mac, &packet).unwrap();
        let ethernet = EthernetFrame::parse(&frame).unwrap();
        assert_eq!(ethernet.ethertype, EtherType::IPv4);
        assert_eq!(ethernet.dst_mac, destination_mac);
        assert_eq!(ethernet.payload, packet.as_slice());
    }

    #[test]
    fn unresolved_ecmp_next_hop_emits_arp_request_for_selected_gateway() {
        let table = table();
        let packet = packet(40_001);
        let parsed = Ipv4Packet::parse(&packet, true).unwrap();
        let selected = table.lookup_best_route_for_flow(flow_key(&parsed)).unwrap();
        let next_hop = selected.next_hop(parsed.header.dst_ip);
        let source_mac = MacAddress::new([0x02, 0, 0, 0, 0, 1]);

        let frame = forward_packet(&table, &HashMap::new(), source_mac, &packet).unwrap();
        let ethernet = EthernetFrame::parse(&frame).unwrap();
        assert_eq!(ethernet.ethertype, EtherType::Arp);
        assert_eq!(ethernet.dst_mac, MacAddress::BROADCAST);
        let arp = ArpPacket::parse(ethernet.payload).unwrap();
        assert_eq!(arp.target_ip, next_hop.0);
    }

    #[test]
    fn invalid_ipv4_checksum_is_fail_closed() {
        let table = table();
        let mut packet = packet(40_002);
        packet[10] ^= 0xff;
        let source_mac = MacAddress::new([0x02, 0, 0, 0, 0, 1]);
        assert!(forward_packet(&table, &HashMap::new(), source_mac, &packet).is_err());
    }
}
